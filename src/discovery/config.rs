//! Discovery configuration: how discovery retries provider requests, how long discovered keys
//! stay fresh, how long requests wait for a refresh, how long discovery waits after a success, how
//! it backs off after failures, and how that delay is jittered. The timing calculations are pure
//! arithmetic, with no async or shared state.

use std::{
    hash::{Hash, Hasher},
    time::Duration,
};

use crate::error::DiscoveryConfigError;

/// How a [`KeycloakAuthInstance`](crate::instance::KeycloakAuthInstance) fetches and refreshes
/// the realm's OIDC discovery document and decoding keys.
///
/// Create one with [`DiscoveryConfig::builder`] and pass it to
/// [`KeycloakAuthInstanceBuilder::discovery_config`](crate::instance::KeycloakAuthInstanceBuilder::discovery_config).
/// [`DiscoveryConfig::default`] uses the `DEFAULT_*` constants of this type.
///
/// A background task owned by the instance refreshes the keys once they are
/// [`refresh_after`](DiscoveryConfigBuilder::refresh_after) old, independently of request traffic,
/// so requests do not wait for routine refreshes. It also retries a failed initial discovery.
/// Validation additionally requests a refresh, shared by concurrent requests, when no usable keys
/// are cached or when no cached key verifies a token with an unknown `kid`.
///
/// After a successful refresh, the next one starts no earlier than a cooldown of about five
/// seconds. After a failed refresh, the delay grows exponentially from about one second to at most
/// one minute. A discovery that takes longer than
/// [`discovery_timeout`](DiscoveryConfigBuilder::discovery_timeout) counts as failed. Keys that
/// are older than [`max_key_age`](DiscoveryConfigBuilder::max_key_age) because refreshes keep
/// failing expire, and [`expired_keys`](DiscoveryConfigBuilder::expired_keys) decides whether they
/// are still used.
///
/// ```
/// use std::time::Duration;
///
/// use axum_keycloak_auth::instance::{DiscoveryConfig, ExpiredKeys};
///
/// let config = DiscoveryConfig::builder()
///     .refresh_after(Duration::from_secs(60))
///     .max_key_age(Duration::from_secs(120))
///     .expired_keys(ExpiredKeys::Reject)
///     .build()?;
/// # Ok::<(), axum_keycloak_auth::error::DiscoveryConfigError>(())
/// ```
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    pub(crate) request_retries: usize,
    pub(crate) request_retry_delay: Duration,
    /// How long one discovery, including its retries, may take before it counts as failed.
    pub(crate) discovery_timeout: Duration,
    pub(crate) success_cooldown: Duration,
    pub(crate) failure_initial_backoff: Duration,
    pub(crate) failure_max_backoff: Duration,
    pub(crate) jitter_basis_points: u16,
    /// How long a request may wait for a shared refresh (including the initial discovery) before
    /// proceeding with the current key set. Bounds request latency when the provider hangs. The
    /// refresh itself continues independently of that waiter while the instance remains owned, and
    /// later requests pick up its result.
    pub(crate) max_refresh_wait: Duration,
    /// How old a key set may get before it is refreshed, without any request waiting for that.
    pub(crate) refresh_after: Duration,
    /// How old a key set may get before [`Self::expired_keys`] decides whether it is still used.
    /// Measured on both the monotonic and the wall clock, by whichever reports more.
    pub(crate) max_key_age: Duration,
    pub(crate) expired_keys: ExpiredKeys,
    /// Whether the instance runs its background refresh task. Always enabled in production. Tests
    /// of request-triggered refreshes disable it to keep refresh counts deterministic.
    pub(crate) background_refresh: bool,
}

/// What an instance does with keys older than
/// [`max_key_age`](DiscoveryConfigBuilder::max_key_age), which only happens while refreshes fail,
/// for example because Keycloak is unreachable.
///
/// Tolerating expired keys keeps the application available during a Keycloak outage, but a key
/// removed from Keycloak, for example because it was compromised, keeps verifying tokens for that
/// long. Anyone who can keep an instance from reaching Keycloak can extend that time.
///
/// Rejected keys make validation fail with
/// [`AuthError::DecodingKeysExpired`](crate::error::AuthError::DecodingKeysExpired), answered with
/// `503 Service Unavailable`, and make
/// [`OperationalStatus::is_operational`](crate::instance::OperationalStatus::is_operational) report
/// `false`, so that a readiness check takes the instance out of rotation. The first successful
/// refresh makes the instance operational again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExpiredKeys {
    /// Keep using expired keys until a refresh succeeds, however long that takes. The key age is
    /// then only bounded while Keycloak is reachable.
    Trust,
    /// Keep using expired keys for at most this long past `max_key_age`, then reject them.
    TrustFor(Duration),
    /// Reject keys as soon as they are older than `max_key_age`.
    Reject,
}

impl ExpiredKeys {
    /// The default for [`DiscoveryConfigBuilder::expired_keys`]: tolerate an outage of one minute
    /// past the maximum key age.
    pub const DEFAULT: Self = Self::TrustFor(Duration::from_secs(60));
}

impl Default for ExpiredKeys {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl DiscoveryConfig {
    /// The default for [`DiscoveryConfigBuilder::request_retries`].
    pub const DEFAULT_REQUEST_RETRIES: usize = 5;

    /// The default for [`DiscoveryConfigBuilder::request_retry_delay`].
    pub const DEFAULT_REQUEST_RETRY_DELAY: Duration = Duration::from_secs(1);

    /// The default for [`DiscoveryConfigBuilder::discovery_timeout`].
    pub const DEFAULT_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(60);

    /// The default for [`DiscoveryConfigBuilder::refresh_after`].
    pub const DEFAULT_REFRESH_AFTER: Duration = Duration::from_secs(4 * 60);

    /// The default for [`DiscoveryConfigBuilder::max_key_age`].
    pub const DEFAULT_MAX_KEY_AGE: Duration = Duration::from_secs(5 * 60);

    /// The shortest [`DiscoveryConfigBuilder::max_key_age`] that
    /// [`DiscoveryConfigBuilder::build`] accepts. It exceeds the cooldown that follows every
    /// successful refresh, so that keys can always be refreshed before they expire.
    pub const MIN_MAX_KEY_AGE: Duration = Duration::from_secs(10);

    /// The default for [`DiscoveryConfigBuilder::max_refresh_wait`].
    pub const DEFAULT_MAX_REFRESH_WAIT: Duration = Duration::from_secs(5);

    const BASIS_POINTS: u64 = 10_000;

    /// Starts from the default configuration.
    pub fn builder() -> DiscoveryConfigBuilder {
        DiscoveryConfigBuilder {
            config: Self::default(),
        }
    }

    /// How old keys may get before they are rejected, or `None` if they are used until a refresh
    /// replaces them.
    pub(super) fn trusted_for(&self) -> Option<Duration> {
        match self.expired_keys {
            ExpiredKeys::Trust => None,
            ExpiredKeys::TrustFor(grace) => self.max_key_age.checked_add(grace),
            ExpiredKeys::Reject => Some(self.max_key_age),
        }
    }

    pub(super) fn success_delay(&self, instance_id: uuid::Uuid, attempt: usize) -> Duration {
        self.jittered(self.success_cooldown, instance_id, attempt)
    }

    pub(super) fn failure_delay(
        &self,
        instance_id: uuid::Uuid,
        consecutive_failures: u32,
        attempt: usize,
    ) -> Duration {
        let exponent = consecutive_failures.saturating_sub(1).min(31);
        let multiplier = 1_u32 << exponent;
        let nominal = self
            .failure_initial_backoff
            .checked_mul(multiplier)
            .unwrap_or(self.failure_max_backoff)
            .min(self.failure_max_backoff);
        self.jittered(nominal, instance_id, attempt)
            .min(self.failure_max_backoff)
    }

    /// Deterministic jitter of up to `jitter_basis_points` around `duration`, decorrelating
    /// instances (by id) and successive attempts without requiring an RNG dependency.
    fn jittered(&self, duration: Duration, instance_id: uuid::Uuid, attempt: usize) -> Duration {
        if self.jitter_basis_points == 0 || duration.is_zero() {
            return duration;
        }

        let mut hasher = std::hash::DefaultHasher::new();
        (instance_id, attempt).hash(&mut hasher);
        let jitter = u64::from(self.jitter_basis_points).min(Self::BASIS_POINTS);
        let sample = hasher.finish() % (jitter * 2 + 1);
        let factor = Self::BASIS_POINTS - jitter + sample;
        let nanos =
            duration.as_nanos().saturating_mul(u128::from(factor)) / u128::from(Self::BASIS_POINTS);
        Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
    }
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            request_retries: Self::DEFAULT_REQUEST_RETRIES,
            request_retry_delay: Self::DEFAULT_REQUEST_RETRY_DELAY,
            discovery_timeout: Self::DEFAULT_DISCOVERY_TIMEOUT,
            success_cooldown: Duration::from_secs(5),
            failure_initial_backoff: Duration::from_secs(1),
            failure_max_backoff: Duration::from_secs(60),
            jitter_basis_points: 2_000,
            max_refresh_wait: Self::DEFAULT_MAX_REFRESH_WAIT,
            refresh_after: Self::DEFAULT_REFRESH_AFTER,
            max_key_age: Self::DEFAULT_MAX_KEY_AGE,
            expired_keys: ExpiredKeys::DEFAULT,
            background_refresh: true,
        }
    }
}

/// Configures a [`DiscoveryConfig`]. Create one with [`DiscoveryConfig::builder`]. Every setting
/// starts at its default.
#[must_use]
#[derive(Debug, Clone)]
pub struct DiscoveryConfigBuilder {
    config: DiscoveryConfig,
}

impl DiscoveryConfigBuilder {
    /// How often a failed request for the discovery document or the JWKS is retried within one
    /// discovery, so each endpoint is requested up to `request_retries + 1` times. Every failure
    /// is retried, including non-success HTTP responses. Defaults to
    /// [`DiscoveryConfig::DEFAULT_REQUEST_RETRIES`].
    ///
    /// Retries apply to the initial discovery and to every refresh, within the overall
    /// [`discovery_timeout`](Self::discovery_timeout). Lower them, or the
    /// [`request_retry_delay`](Self::request_retry_delay), if a failing refresh should give up
    /// sooner. Requests stop waiting for it after [`max_refresh_wait`](Self::max_refresh_wait)
    /// either way.
    pub fn request_retries(mut self, request_retries: usize) -> Self {
        self.config.request_retries = request_retries;
        self
    }

    /// The fixed delay before each retry of a failed request. Defaults to
    /// [`DiscoveryConfig::DEFAULT_REQUEST_RETRY_DELAY`].
    pub fn request_retry_delay(mut self, request_retry_delay: Duration) -> Self {
        self.config.request_retry_delay = request_retry_delay;
        self
    }

    /// How long one discovery, both endpoints and all their retries included, may take before it
    /// is abandoned and counts as failed. Defaults to
    /// [`DiscoveryConfig::DEFAULT_DISCOVERY_TIMEOUT`]. Must not be zero.
    ///
    /// Only one discovery runs at a time. Without this bound, a Keycloak that accepts connections
    /// but never answers, together with an HTTP client without timeouts, would block every later
    /// refresh. Configure timeouts for single requests on the HTTP client.
    pub fn discovery_timeout(mut self, discovery_timeout: Duration) -> Self {
        self.config.discovery_timeout = discovery_timeout;
        self
    }

    /// How old the cached keys may get before the background task refreshes them. Defaults to
    /// [`DiscoveryConfig::DEFAULT_REFRESH_AFTER`]. Must be less than
    /// [`max_key_age`](Self::max_key_age).
    ///
    /// The refresh runs independently of requests, so none of them waits for it. Keep a margin
    /// to `max_key_age`, so that a failing refresh is retried a few times before the keys expire.
    /// A successful refresh is followed by a cooldown of about five seconds, so shorter ages
    /// behave like that cooldown.
    pub fn refresh_after(mut self, refresh_after: Duration) -> Self {
        self.config.refresh_after = refresh_after;
        self
    }

    /// How old the cached keys may get, counted from the last successful refresh, before they
    /// expire and [`expired_keys`](Self::expired_keys) decides whether they are still used.
    /// Defaults to [`DiscoveryConfig::DEFAULT_MAX_KEY_AGE`]. Must be at least
    /// [`DiscoveryConfig::MIN_MAX_KEY_AGE`].
    ///
    /// Together with `expired_keys`, this bounds how long a key removed from Keycloak, for example
    /// because it was compromised, keeps verifying tokens. Changed key material under an existing
    /// `kid` is picked up by the same refreshes.
    ///
    /// The age is measured on both the monotonic and the wall clock, by whichever reports more,
    /// so that time the system spent suspended counts as well. After such a suspension, the first
    /// request refreshes the keys and, if Keycloak answers, waits for that refresh.
    pub fn max_key_age(mut self, max_key_age: Duration) -> Self {
        self.config.max_key_age = max_key_age;
        self
    }

    /// What happens with keys older than [`max_key_age`](Self::max_key_age), which only occurs
    /// while refreshes fail. Defaults to [`ExpiredKeys::DEFAULT`], which tolerates such keys for
    /// one more minute.
    pub fn expired_keys(mut self, expired_keys: ExpiredKeys) -> Self {
        self.config.expired_keys = expired_keys;
        self
    }

    /// How long a request waits for a shared refresh, including the initial discovery, before it
    /// continues with the current key set. Defaults to
    /// [`DiscoveryConfig::DEFAULT_MAX_REFRESH_WAIT`].
    ///
    /// This bounds the latency a slow or unreachable Keycloak adds to requests. The refresh itself
    /// continues in the background, and later requests use its result. Requests do not wait for a
    /// refresh that started longer than this ago, and do not wait for refreshes of expired keys
    /// after a failed attempt. `Duration::ZERO` never delays requests, so the request that
    /// triggers a refresh is validated against the keys cached before it.
    pub fn max_refresh_wait(mut self, max_refresh_wait: Duration) -> Self {
        self.config.max_refresh_wait = max_refresh_wait;
        self
    }

    /// Creates the configuration.
    ///
    /// # Errors
    ///
    /// Returns a [`DiscoveryConfigError`] for settings that would make keys expire before they
    /// can be refreshed, or that would abandon every discovery immediately. The rules apply
    /// whatever [`ExpiredKeys`] is configured.
    pub fn build(self) -> Result<DiscoveryConfig, DiscoveryConfigError> {
        let config = self.config;
        if config.discovery_timeout.is_zero() {
            return Err(DiscoveryConfigError::ZeroDiscoveryTimeout);
        }
        if config.max_key_age < DiscoveryConfig::MIN_MAX_KEY_AGE {
            return Err(DiscoveryConfigError::MaxKeyAgeTooShort {
                max_key_age: config.max_key_age,
                minimum: DiscoveryConfig::MIN_MAX_KEY_AGE,
            });
        }
        if config.refresh_after >= config.max_key_age {
            return Err(DiscoveryConfigError::RefreshAfterNotBelowMaxKeyAge {
                refresh_after: config.refresh_after,
                max_key_age: config.max_key_age,
            });
        }
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, time::Duration};

    use assertr::prelude::*;

    use crate::error::DiscoveryConfigError;

    use super::{DiscoveryConfig, DiscoveryConfigBuilder, ExpiredKeys};

    #[test]
    fn discovery_config_uses_the_selected_cooldown_and_exponential_backoff() {
        let config = DiscoveryConfig {
            jitter_basis_points: 0,
            ..DiscoveryConfig::default()
        };
        let instance_id = uuid::Uuid::from_u128(1);

        assert_that!(config.success_delay(instance_id, 1)).is_equal_to(Duration::from_secs(5));
        for (failures, expected_seconds) in [
            (1, 1),
            (2, 2),
            (3, 4),
            (4, 8),
            (5, 16),
            (6, 32),
            (7, 60),
            (8, 60),
        ] {
            assert_that!(config.failure_delay(
                instance_id,
                failures,
                usize::try_from(failures).expect("small failure count fits usize"),
            ))
            .is_equal_to(Duration::from_secs(expected_seconds));
        }
    }

    #[test]
    fn builder_overrides_only_the_given_settings() {
        let config = DiscoveryConfig::builder()
            .request_retries(2)
            .request_retry_delay(Duration::from_millis(250))
            .refresh_after(Duration::from_secs(20))
            .max_key_age(Duration::from_secs(30))
            .expired_keys(ExpiredKeys::Reject)
            .max_refresh_wait(Duration::from_secs(1))
            .discovery_timeout(Duration::from_secs(7))
            .build()
            .expect("a refresh before the maximum key age must build");
        assert_that!(config.request_retries).is_equal_to(2);
        assert_that!(config.request_retry_delay).is_equal_to(Duration::from_millis(250));
        assert_that!(config.refresh_after).is_equal_to(Duration::from_secs(20));
        assert_that!(config.max_key_age).is_equal_to(Duration::from_secs(30));
        assert_that!(config.expired_keys).is_equal_to(ExpiredKeys::Reject);
        assert_that!(config.max_refresh_wait).is_equal_to(Duration::from_secs(1));
        assert_that!(config.discovery_timeout).is_equal_to(Duration::from_secs(7));
        assert_that!(config.success_cooldown).is_equal_to(Duration::from_secs(5));

        let defaults = DiscoveryConfig::builder()
            .build()
            .expect("the default configuration must build");
        assert_that!(defaults.request_retries).is_equal_to(5);
        assert_that!(defaults.request_retry_delay).is_equal_to(Duration::from_secs(1));
        assert_that!(defaults.refresh_after).is_equal_to(Duration::from_secs(4 * 60));
        assert_that!(defaults.max_key_age).is_equal_to(Duration::from_secs(5 * 60));
        assert_that!(defaults.expired_keys)
            .is_equal_to(ExpiredKeys::TrustFor(Duration::from_secs(60)));
        assert_that!(defaults.max_refresh_wait).is_equal_to(Duration::from_secs(5));
        assert_that!(defaults.discovery_timeout).is_equal_to(Duration::from_secs(60));
        assert_that!(defaults.background_refresh).is_true();
    }

    #[test]
    fn inconsistent_settings_are_rejected() {
        let build = |builder: DiscoveryConfigBuilder| builder.build().map(|_config| ());
        let ages = |refresh_after, max_key_age| {
            DiscoveryConfig::builder()
                .refresh_after(Duration::from_secs(refresh_after))
                .max_key_age(Duration::from_secs(max_key_age))
        };

        assert_that!(build(ages(29, 30))).is_ok();
        assert_that!(build(ages(30, 30))).is_equal_to(Err(
            DiscoveryConfigError::RefreshAfterNotBelowMaxKeyAge {
                refresh_after: Duration::from_secs(30),
                max_key_age: Duration::from_secs(30),
            },
        ));
        assert_that!(build(ages(0, 10))).is_ok();
        assert_that!(build(ages(0, 9))).is_equal_to(Err(DiscoveryConfigError::MaxKeyAgeTooShort {
            max_key_age: Duration::from_secs(9),
            minimum: Duration::from_secs(10),
        }));
        assert_that!(build(ages(0, 0).expired_keys(ExpiredKeys::Trust))).is_equal_to(Err(
            DiscoveryConfigError::MaxKeyAgeTooShort {
                max_key_age: Duration::ZERO,
                minimum: Duration::from_secs(10),
            },
        ));
        assert_that!(build(
            DiscoveryConfig::builder().discovery_timeout(Duration::ZERO)
        ))
        .is_equal_to(Err(DiscoveryConfigError::ZeroDiscoveryTimeout));
    }

    #[test]
    fn expired_keys_decides_how_long_keys_are_trusted() {
        let with = |expired_keys| DiscoveryConfig {
            expired_keys,
            ..DiscoveryConfig::default()
        };

        assert_that!(with(ExpiredKeys::Trust).trusted_for()).is_none();
        assert_that!(with(ExpiredKeys::Reject).trusted_for())
            .is_equal_to(Some(Duration::from_secs(5 * 60)));
        assert_that!(with(ExpiredKeys::TrustFor(Duration::from_secs(60))).trusted_for())
            .is_equal_to(Some(Duration::from_secs(6 * 60)));
        assert_that!(with(ExpiredKeys::TrustFor(Duration::MAX)).trusted_for()).is_none();
    }

    #[test]
    fn production_refresh_jitter_is_bounded_and_decorrelates_instances() {
        let config = DiscoveryConfig::default();
        let delays = (1..=16)
            .map(|id| config.success_delay(uuid::Uuid::from_u128(id), 2))
            .collect::<BTreeSet<_>>();

        assert_that!(delays.len()).is_greater_than(1);
        for delay in &delays {
            assert_that!(delay).is_in_range(Duration::from_secs(4)..=Duration::from_secs(6));
        }
        for id in 1..=16 {
            assert_that!(config.failure_delay(uuid::Uuid::from_u128(id), 1, 2))
                .is_less_or_equal_to(Duration::from_millis(1_200));
            assert_that!(config.failure_delay(uuid::Uuid::from_u128(id), 7, 8))
                .is_less_or_equal_to(Duration::from_secs(60));
        }
    }
}
