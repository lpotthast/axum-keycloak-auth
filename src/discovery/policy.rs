//! Refresh timing policy: how long discovery waits after a success, how it backs off after
//! failures, and how that delay is jittered. Pure arithmetic, with no async or shared state.

use std::{
    hash::{Hash, Hasher},
    time::Duration,
};

#[derive(Debug, Clone, Copy)]
pub(crate) struct RefreshPolicy {
    pub(crate) success_cooldown: Duration,
    pub(crate) failure_initial_backoff: Duration,
    pub(crate) failure_max_backoff: Duration,
    pub(crate) jitter_basis_points: u16,
    /// How long a request may wait for a shared refresh (including the initial discovery) before
    /// proceeding with the current key set. Bounds request latency when the provider hangs. The
    /// refresh itself continues independently of that waiter while the instance remains owned, and
    /// later requests pick up its result.
    pub(crate) max_refresh_wait: Duration,
}

impl RefreshPolicy {
    const BASIS_POINTS: u64 = 10_000;

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

impl Default for RefreshPolicy {
    fn default() -> Self {
        Self {
            success_cooldown: Duration::from_secs(5),
            failure_initial_backoff: Duration::from_secs(1),
            failure_max_backoff: Duration::from_secs(60),
            jitter_basis_points: 2_000,
            max_refresh_wait: Duration::from_secs(5),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, time::Duration};

    use assertr::prelude::*;

    use super::RefreshPolicy;

    #[test]
    fn refresh_policy_uses_the_selected_cooldown_and_exponential_backoff() {
        let policy = RefreshPolicy {
            jitter_basis_points: 0,
            ..RefreshPolicy::default()
        };
        let instance_id = uuid::Uuid::from_u128(1);

        assert_that!(policy.success_delay(instance_id, 1)).is_equal_to(Duration::from_secs(5));
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
            assert_that!(policy.failure_delay(
                instance_id,
                failures,
                usize::try_from(failures).expect("small failure count fits usize"),
            ))
            .is_equal_to(Duration::from_secs(expected_seconds));
        }
    }

    #[test]
    fn production_refresh_jitter_is_bounded_and_decorrelates_instances() {
        let policy = RefreshPolicy::default();
        let delays = (1..=16)
            .map(|id| policy.success_delay(uuid::Uuid::from_u128(id), 2))
            .collect::<BTreeSet<_>>();

        assert_that!(delays.len()).is_greater_than(1);
        for delay in &delays {
            assert_that!(delay).is_in_range(Duration::from_secs(4)..=Duration::from_secs(6));
        }
        for id in 1..=16 {
            assert_that!(policy.failure_delay(uuid::Uuid::from_u128(id), 1, 2))
                .is_less_or_equal_to(Duration::from_millis(1_200));
            assert_that!(policy.failure_delay(uuid::Uuid::from_u128(id), 7, 8))
                .is_less_or_equal_to(Duration::from_secs(60));
        }
    }
}
