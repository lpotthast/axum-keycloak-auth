//! Single-flight discovery, refresh timing state, cached generations, and health reporting.
//!
//! A completed transition publishes its key data and generation together before waking waiters.
//! The lifecycle drives any supplied [`DiscoveryOp`] and does not depend on [`super::provider`].

use std::{
    fmt::Debug,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use futures::FutureExt;
use tokio::sync::watch;

use crate::{clock::Clock, error::AuthError};

use super::{
    DecodingKeys, DiscoveredData, DiscoveryKind, DiscoveryOp, DiscoveryRequest, DiscoveryResult,
    OidcDiscoveryEndpoint, RefreshPolicy,
};

#[derive(Debug)]
enum RefreshError {
    Discovery(AuthError),
    NoUsableDecodingKeys,
    Panicked,
}

impl RefreshError {
    /// A single-line description including the complete source chain, so that health reporting
    /// shows the actual transport or decoding reason instead of only the top-level category.
    fn message(&self) -> String {
        match self {
            RefreshError::Discovery(error) => {
                let mut message = error.to_string();
                let mut source = std::error::Error::source(error);
                while let Some(cause) = source {
                    message.push_str(": ");
                    message.push_str(&cause.to_string());
                    source = cause.source();
                }
                message
            }
            RefreshError::NoUsableDecodingKeys => {
                String::from("The provider returned no usable decoding keys")
            }
            RefreshError::Panicked => String::from("The discovery operation panicked"),
        }
    }
}

/// A point-in-time view of OIDC discovery and key refresh state.
///
/// Obtain this through
/// [`KeycloakAuthInstance::operational_status`](crate::instance::KeycloakAuthInstance::operational_status).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct OperationalStatus {
    /// Whether at least one usable decoding key is available.
    pub is_operational: bool,
    /// Time since the last successful discovery completed.
    pub time_since_last_success: Option<Duration>,
    /// Time since the most recent discovery attempt started.
    pub time_since_last_attempt: Option<Duration>,
    /// The latest failure, or `None` after a successful discovery with no later failure.
    pub last_error: Option<DiscoveryFailure>,
    /// Consecutive failed attempts since startup or the latest success.
    pub consecutive_failures: u32,
}

/// A failed OIDC discovery or key refresh, as reported by [`OperationalStatus::last_error`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DiscoveryFailure {
    /// The error, including its source chain.
    pub message: String,
    /// Time elapsed since the failure.
    pub elapsed: Duration,
}

#[derive(Debug)]
struct RefreshState {
    last_successful_at: Option<Instant>,
    last_attempted_at: Option<Instant>,
    last_error: Option<(Instant, RefreshError)>,
    consecutive_failures: u32,
    /// The earliest instant at which a new on-demand refresh may start. Only consulted while no
    /// discovery is pending. Set by every discovery that succeeds or fails, except that a
    /// successful initial discovery clears it so the first token with an unknown `kid` may refresh
    /// immediately. A discovery whose task is dropped before it finishes leaves it untouched,
    /// whether a shutting-down runtime dropped it, the last lifecycle owner aborted it, or it could
    /// not be spawned outside a runtime.
    next_refresh_at: Option<Instant>,
    /// Whether a discovery is currently in flight. Guarded by the surrounding lock, this is what
    /// makes refreshes single-flight.
    pending: bool,
}

impl RefreshState {
    fn initial(now: Instant) -> Self {
        Self {
            last_successful_at: None,
            last_attempted_at: Some(now),
            last_error: None,
            consecutive_failures: 0,
            next_refresh_at: None,
            pending: true,
        }
    }

    #[cfg(test)]
    fn resolved(now: Instant) -> Self {
        Self {
            last_successful_at: Some(now),
            last_attempted_at: Some(now),
            last_error: None,
            consecutive_failures: 0,
            next_refresh_at: None,
            pending: false,
        }
    }

    fn begin_on_demand(&mut self, now: Instant) {
        self.pending = true;
        self.last_attempted_at = Some(now);
    }

    fn finish(
        &mut self,
        request: &DiscoveryRequest,
        result: DiscoveryResult,
        current_data: Option<Arc<DiscoveredData>>,
        now: Instant,
        instance_id: uuid::Uuid,
        policy: RefreshPolicy,
    ) -> Option<Arc<DiscoveredData>> {
        match result {
            Ok(data) if !data.has_usable_decoding_keys() => {
                self.record_failure(
                    request,
                    RefreshError::NoUsableDecodingKeys,
                    now,
                    instance_id,
                    policy,
                );
                current_data
            }
            Ok(data) => {
                self.last_successful_at = Some(now);
                self.last_error = None;
                self.consecutive_failures = 0;
                self.next_refresh_at = match request.kind {
                    DiscoveryKind::Initial => None,
                    DiscoveryKind::OnDemand => {
                        now.checked_add(policy.success_delay(instance_id, request.attempt))
                    }
                };
                Some(data)
            }
            Err(error) => {
                self.record_failure(
                    request,
                    RefreshError::Discovery(error),
                    now,
                    instance_id,
                    policy,
                );
                current_data
            }
        }
    }

    fn record_failure(
        &mut self,
        request: &DiscoveryRequest,
        error: RefreshError,
        now: Instant,
        instance_id: uuid::Uuid,
        policy: RefreshPolicy,
    ) {
        match &error {
            RefreshError::Discovery(_) | RefreshError::NoUsableDecodingKeys => {
                tracing::warn!(
                    error = %error.message(),
                    "OIDC refresh failed; keeping the previous cache state."
                );
            }
            RefreshError::Panicked => {
                tracing::error!(
                    error = %error.message(),
                    "OIDC refresh panicked; keeping the previous cache state."
                );
            }
        }
        self.last_error = Some((now, error));
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.next_refresh_at = now.checked_add(policy.failure_delay(
            instance_id,
            self.consecutive_failures,
            request.attempt,
        ));
    }
}

enum DispatchOutcome {
    Completed(DiscoveryResult),
    Panicked,
    Cancelled,
}

/// Completes the refresh state transition even when Tokio drops the detached task before its
/// operation resolves, such as when the task's originating runtime is destroyed.
struct DispatchGuard {
    request: DiscoveryRequest,
    refresh_state: Arc<Mutex<RefreshState>>,
    published: watch::Sender<(usize, Option<Arc<DiscoveredData>>)>,
    clock: Arc<dyn Clock>,
    instance_id: uuid::Uuid,
    policy: RefreshPolicy,
    armed: bool,
}

impl DispatchGuard {
    fn new(
        request: DiscoveryRequest,
        refresh_state: Arc<Mutex<RefreshState>>,
        published: watch::Sender<(usize, Option<Arc<DiscoveredData>>)>,
        clock: Arc<dyn Clock>,
        instance_id: uuid::Uuid,
        policy: RefreshPolicy,
    ) -> Self {
        Self {
            request,
            refresh_state,
            published,
            clock,
            instance_id,
            policy,
            armed: true,
        }
    }

    fn complete(mut self, outcome: DispatchOutcome) {
        // Disarm before publishing so an unexpected panic in bookkeeping cannot make Drop try the
        // same transition again while the thread is already unwinding.
        self.armed = false;
        self.publish(outcome);
    }

    fn publish(&self, outcome: DispatchOutcome) {
        let mut state = self
            .refresh_state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let now = self.clock.now_monotonic();
        let current_data = self.published.borrow().1.clone();
        let data = match outcome {
            DispatchOutcome::Completed(result) => state.finish(
                &self.request,
                result,
                current_data,
                now,
                self.instance_id,
                self.policy,
            ),
            DispatchOutcome::Panicked => {
                state.record_failure(
                    &self.request,
                    RefreshError::Panicked,
                    now,
                    self.instance_id,
                    self.policy,
                );
                current_data
            }
            // The task was dropped before its operation finished: its runtime shut down, the last
            // lifecycle owner aborted it, or it could not be spawned outside a runtime. None of
            // this says anything about the provider. Neither record a failure nor back off, so
            // that a later runtime may retry immediately.
            DispatchOutcome::Cancelled => {
                tracing::debug!("OIDC refresh was cancelled; keeping the previous cache state.");
                current_data
            }
        };
        state.pending = false;
        self.published.send_modify(|(generation, published_data)| {
            *generation += 1;
            *published_data = data;
        });
    }
}

impl Drop for DispatchGuard {
    fn drop(&mut self) {
        if self.armed {
            self.publish(DispatchOutcome::Cancelled);
        }
    }
}

/// Owns the discovery lifecycle: the cached provider data, single-flight on-demand refreshes with
/// cooldown/backoff, and the completion signal callers wait on.
pub(crate) struct Discovery {
    instance_id: uuid::Uuid,
    endpoint: OidcDiscoveryEndpoint,
    op: DiscoveryOp,
    refresh_state: Arc<Mutex<RefreshState>>,
    /// Atomically publishes each terminated discovery's generation and resulting cached data,
    /// and doubles as the completion signal for waiters.
    published: watch::Sender<(usize, Option<Arc<DiscoveredData>>)>,
    /// Cancels the detached operation when this last lifecycle owner is dropped. A completed
    /// operation may leave a stale handle here until the next spawn. Aborting it is harmless.
    in_flight_abort: Mutex<Option<tokio::task::AbortHandle>>,
    clock: Arc<dyn Clock>,
    policy: RefreshPolicy,
}

impl Debug for Discovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Discovery")
            .field("instance_id", &self.instance_id)
            .field("endpoint", &self.endpoint)
            .field("generation", &self.published.borrow().0)
            .finish_non_exhaustive()
    }
}

impl Discovery {
    /// Creates the discovery lifecycle and immediately spawns the initial discovery.
    pub(crate) fn new(
        endpoint: OidcDiscoveryEndpoint,
        op: DiscoveryOp,
        instance_id: uuid::Uuid,
        clock: Arc<dyn Clock>,
        policy: RefreshPolicy,
    ) -> Self {
        let discovery = Self {
            instance_id,
            endpoint,
            op,
            refresh_state: Arc::new(Mutex::new(RefreshState::initial(clock.now_monotonic()))),
            published: watch::Sender::new((0, None)),
            in_flight_abort: Mutex::new(None),
            clock,
            policy,
        };
        discovery.spawn(DiscoveryRequest {
            attempt: 1,
            kind: DiscoveryKind::Initial,
        });
        discovery
    }

    /// Runs one discovery in a task detached from individual waiters, so it completes if those
    /// waiters are cancelled while this lifecycle remains owned. Dropping the lifecycle aborts the
    /// task. Every termination publishes the next snapshot and wakes remaining waiters.
    fn spawn(&self, request: DiscoveryRequest) {
        // Serialize spawning through the handle slot. A spawned task can finish immediately on
        // another runtime thread; holding this lock prevents an older spawn from subsequently
        // overwriting the abort handle installed by a newer refresh.
        let mut in_flight_abort = self
            .in_flight_abort
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let operation = self.op.clone();
        let endpoint = self.endpoint.clone();
        let operation_request = request.clone();
        // Construct the guard before the async body so dropping an unpolled spawned task still
        // terminates the attempt and clears the single-flight marker.
        let guard = DispatchGuard::new(
            request,
            self.refresh_state.clone(),
            self.published.clone(),
            self.clock.clone(),
            self.instance_id,
            self.policy,
        );
        let abort_handle = tokio::spawn(async move {
            let operation = async move { operation(endpoint, operation_request).await };
            match std::panic::AssertUnwindSafe(operation).catch_unwind().await {
                Ok(result) => guard.complete(DispatchOutcome::Completed(result)),
                Err(_panic) => guard.complete(DispatchOutcome::Panicked),
            }
        })
        .abort_handle();
        *in_flight_abort = Some(abort_handle);
    }

    /// Starts or joins one shared refresh and waits for it, unless a refresh already completed
    /// after `observed_generation` or the refresh policy's cooldown/backoff still applies.
    ///
    /// The wait is capped by the policy's `max_refresh_wait`, so a stalled provider does not block
    /// requests indefinitely. The refresh itself continues independently of this waiter while the
    /// lifecycle remains owned.
    ///
    /// Returns whether a discovery terminated after `observed_generation`, meaning the cached data
    /// may have changed and a retry is worthwhile. A terminated discovery may also have failed or
    /// been dropped and left the data as it was, so `true` does not guarantee new keys.
    pub(crate) async fn refresh_if_needed(&self, observed_generation: usize) -> bool {
        let request = {
            let now = self.clock.now_monotonic();
            let mut state = self
                .refresh_state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let generation = self.published.borrow().0;
            if generation > observed_generation {
                return true;
            }
            if state.pending {
                None
            } else {
                if state.next_refresh_at.is_some_and(|deadline| now < deadline) {
                    return false;
                }
                let request = DiscoveryRequest {
                    attempt: generation.saturating_add(1),
                    kind: DiscoveryKind::OnDemand,
                };
                state.begin_on_demand(now);
                Some(request)
            }
        };
        // Spawn outside the refresh-state lock: during runtime shutdown, Tokio can drop the new
        // task synchronously here, and the dispatch guard then needs to re-lock that state.
        if let Some(request) = request {
            self.spawn(request);
        }

        let wait_for_refresh = async {
            let mut snapshots = self.published.subscribe();
            while snapshots.borrow_and_update().0 <= observed_generation {
                if snapshots.changed().await.is_err() {
                    return;
                }
            }
        };
        if tokio::time::timeout(self.policy.max_refresh_wait, wait_for_refresh)
            .await
            .is_err()
        {
            tracing::warn!(
                "Timed out waiting for a shared OIDC discovery refresh; continuing with the current key set."
            );
        }
        self.published.borrow().0 > observed_generation
    }

    /// Returns true after discovery has produced at least one usable decoding key.
    pub(crate) fn is_operational(&self) -> bool {
        self.published
            .borrow()
            .1
            .as_ref()
            .is_some_and(|data| data.has_usable_decoding_keys())
    }

    pub(crate) fn decoding_keys(&self) -> DecodingKeys {
        let snapshot = self.published.borrow();
        DecodingKeys::new(snapshot.1.clone(), snapshot.0)
    }

    /// Waits until at least `expected_completion` discovery attempts have terminated,
    /// successfully or not.
    pub(crate) async fn wait_for_completion(&self, expected_completion: usize) {
        let mut snapshots = self.published.subscribe();
        while snapshots.borrow_and_update().0 < expected_completion {
            if snapshots.changed().await.is_err() {
                return;
            }
        }
    }

    /// The `AuthError` of the most recent failed discovery, if the most recent error was one.
    pub(crate) fn last_discovery_error(&self) -> Option<AuthError> {
        let state = self
            .refresh_state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match &state.last_error {
            Some((_at, RefreshError::Discovery(error))) => Some(error.clone()),
            Some((_at, RefreshError::NoUsableDecodingKeys)) => Some(AuthError::NoDecodingKeys),
            _ => None,
        }
    }

    pub(crate) fn operational_status(&self) -> OperationalStatus {
        let now = self.clock.now_monotonic();
        let state = self
            .refresh_state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        OperationalStatus {
            is_operational: self
                .published
                .borrow()
                .1
                .as_ref()
                .is_some_and(|data| data.has_usable_decoding_keys()),
            time_since_last_success: state
                .last_successful_at
                .map(|at| now.saturating_duration_since(at)),
            time_since_last_attempt: state
                .last_attempted_at
                .map(|at| now.saturating_duration_since(at)),
            last_error: state
                .last_error
                .as_ref()
                .map(|(at, error)| DiscoveryFailure {
                    message: error.message(),
                    elapsed: now.saturating_duration_since(*at),
                }),
            consecutive_failures: state.consecutive_failures,
        }
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> RefreshStateSnapshot {
        let state = self
            .refresh_state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        RefreshStateSnapshot {
            last_successful_at: state.last_successful_at,
            last_attempted_at: state.last_attempted_at,
            last_error_at: state.last_error.as_ref().map(|(at, _error)| *at),
            consecutive_failures: state.consecutive_failures,
            next_refresh_at: state.next_refresh_at,
            pending: state.pending,
            generation: self.published.borrow().0,
        }
    }

    #[cfg(test)]
    pub(crate) fn resolved(endpoint: OidcDiscoveryEndpoint, data: DiscoveredData) -> Self {
        let clock: Arc<dyn Clock> = Arc::new(crate::clock::SystemClock);
        let now = clock.now_monotonic();
        Self {
            instance_id: uuid::Uuid::now_v7(),
            endpoint,
            op: Arc::new(|_endpoint, _request| {
                Box::pin(async { panic!("a resolved test discovery cannot re-discover") })
            }),
            refresh_state: Arc::new(Mutex::new(RefreshState::resolved(now))),
            published: watch::Sender::new((1, Some(Arc::new(data)))),
            in_flight_abort: Mutex::new(None),
            clock,
            policy: RefreshPolicy::default(),
        }
    }
}

impl Drop for Discovery {
    fn drop(&mut self) {
        if let Some(abort_handle) = self
            .in_flight_abort
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            abort_handle.abort();
        }
    }
}

#[cfg(test)]
pub(crate) struct RefreshStateSnapshot {
    pub(crate) last_successful_at: Option<Instant>,
    pub(crate) last_attempted_at: Option<Instant>,
    pub(crate) last_error_at: Option<Instant>,
    pub(crate) consecutive_failures: u32,
    pub(crate) next_refresh_at: Option<Instant>,
    pub(crate) pending: bool,
    pub(crate) generation: usize,
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc, Mutex, PoisonError,
            atomic::{AtomicBool, AtomicUsize, Ordering},
            mpsc,
        },
        time::Duration,
    };

    use assertr::{
        matchers::{IsFalse, IsNone, IsSome, eq},
        prelude::*,
    };
    use jsonwebtoken::Algorithm;

    use crate::{
        clock::{Clock, SystemClock},
        discovery::default_discovery_op,
        http::default_http_client,
        server_url::ServerUrl,
        test_support::{
            ManualClock, MockOidcServer, RSA_KEY_A, RSA_KEY_B, TEST_REALM, TEST_TIMEOUT,
            refresh_policy_without_jitter, static_discovered_data, test_server_url, wait_until,
            within_test_timeout,
        },
    };

    use super::{Discovery, OidcDiscoveryEndpoint, RefreshPolicy, RefreshStateSnapshot};

    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// A `Discovery` driving the production operation against the mock provider, with its
    /// initial discovery attempt terminated.
    async fn discovery_against(
        provider: &MockOidcServer,
        clock: Arc<dyn Clock>,
        policy: RefreshPolicy,
    ) -> Discovery {
        let server = ServerUrl::new(provider.server_url())
            .expect("the mock provider URL must serve as a base URL");
        let endpoint = OidcDiscoveryEndpoint::new(&server, provider.realm());
        let op = default_discovery_op(
            default_http_client(),
            uuid::Uuid::from_u128(1),
            provider.server_url().to_string(),
            provider.realm().to_owned(),
            (1, 0),
        );
        let discovery = Discovery::new(endpoint, op, uuid::Uuid::from_u128(1), clock, policy);
        within_test_timeout(
            "the initial discovery attempt must terminate",
            discovery.wait_for_completion(1),
        )
        .await;
        discovery
    }

    /// A clock whose first monotonic reading blocks until the test releases it, signalling once
    /// it is blocked.
    struct BlockingMonotonicClock {
        inner: Arc<ManualClock>,
        block_next: AtomicBool,
        blocked: Mutex<Option<mpsc::SyncSender<()>>>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    impl Clock for BlockingMonotonicClock {
        fn now_utc(&self) -> time::OffsetDateTime {
            self.inner.now_utc()
        }

        fn now_monotonic(&self) -> std::time::Instant {
            if self.block_next.swap(false, Ordering::SeqCst) {
                self.blocked
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take()
                    .expect("the blocking clock must signal exactly once")
                    .send(())
                    .expect("the test must still be waiting for the clock to block");
                self.release
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .recv()
                    .expect("the test must release the blocked clock");
            }
            self.inner.now_monotonic()
        }
    }

    /// The discovery endpoint of the offline fixture realm, which is never contacted.
    fn fixture_endpoint() -> OidcDiscoveryEndpoint {
        let server = ServerUrl::new(test_server_url())
            .expect("the fixture server URL must serve as a base URL");
        OidcDiscoveryEndpoint::new(&server, TEST_REALM)
    }

    fn key_a() -> jsonwebtoken::jwk::Jwk {
        RSA_KEY_A.jwk(Some("key-a"), Algorithm::RS256)
    }

    fn key_b() -> jsonwebtoken::jwk::Jwk {
        RSA_KEY_B.jwk(Some("key-b"), Algorithm::RS256)
    }

    #[tokio::test]
    async fn successful_refresh_cooldown_uses_the_exact_deadline() {
        let provider = MockOidcServer::start().await;
        provider.set_jwks(vec![key_a()]).await;
        let clock = ManualClock::at_validation_time();
        let discovery =
            discovery_against(&provider, clock.clone(), refresh_policy_without_jitter()).await;

        // Generation 1 is the initial discovery; observing it starts one on-demand refresh.
        assert_that!(discovery.refresh_if_needed(1).await).is_true();
        assert_that!(provider.discovery_requests()).is_equal_to(2);

        // The success cooldown blocks further refreshes up to its exact deadline.
        clock.advance(time::Duration::milliseconds(4_999));
        assert_that!(discovery.refresh_if_needed(2).await).is_false();
        assert_that!(provider.discovery_requests()).is_equal_to(2);

        clock.advance(time::Duration::milliseconds(1));
        assert_that!(discovery.refresh_if_needed(2).await).is_true();
        assert_that!(provider.discovery_requests()).is_equal_to(3);
        assert_that!(provider.jwks_requests()).is_equal_to(3);
    }

    #[tokio::test]
    async fn failed_refresh_backoff_grows_and_resets_after_success() {
        let provider = MockOidcServer::start().await;
        provider.set_jwks(vec![key_a()]).await;
        let clock = ManualClock::at_validation_time();
        let discovery =
            discovery_against(&provider, clock.clone(), refresh_policy_without_jitter()).await;
        provider.make_discovery_unavailable().await;

        // A failed refresh (`retry((1, 0))`: one request plus one retry) starts the 1s backoff.
        // It still publishes a new generation, so the call reports one.
        assert_that!(discovery.refresh_if_needed(1).await).is_true();
        assert_that!(discovery.snapshot().consecutive_failures).is_equal_to(1);
        assert_that!(provider.discovery_requests()).is_equal_to(3);
        clock.advance(time::Duration::milliseconds(999));
        assert_that!(discovery.refresh_if_needed(2).await).is_false();
        assert_that!(provider.discovery_requests()).is_equal_to(3);

        // The second failure doubles the backoff.
        clock.advance(time::Duration::milliseconds(1));
        assert_that!(discovery.refresh_if_needed(2).await).is_true();
        assert_that!(discovery.snapshot().consecutive_failures).is_equal_to(2);
        assert_that!(provider.discovery_requests()).is_equal_to(5);

        provider.restore_discovery_response().await;
        clock.advance(time::Duration::milliseconds(1_999));
        assert_that!(discovery.refresh_if_needed(3).await).is_false();
        assert_that!(provider.discovery_requests()).is_equal_to(5);

        // A success at the exact backoff deadline ends the failure streak.
        clock.advance(time::Duration::milliseconds(1));
        assert_that!(discovery.refresh_if_needed(3).await).is_true();
        assert_that!(provider.discovery_requests()).is_equal_to(6);
        assert_that!(discovery.snapshot().consecutive_failures).is_equal_to(0);
    }

    #[tokio::test]
    async fn capped_refresh_wait_returns_instead_of_hanging() {
        let provider = MockOidcServer::start().await;
        provider.set_jwks(vec![key_a()]).await;
        let discovery = discovery_against(
            &provider,
            Arc::new(SystemClock),
            RefreshPolicy {
                jitter_basis_points: 0,
                max_refresh_wait: Duration::from_millis(50),
                ..RefreshPolicy::default()
            },
        )
        .await;
        let gate = provider.set_gated_jwks(vec![key_b()]).await;

        // The capped wait reports no newer generation instead of hanging on the gated provider,
        // so a request degrades to the current key set; the refresh itself continues detached.
        let refreshed = within_test_timeout(
            "a capped refresh wait must return instead of hanging",
            discovery.refresh_if_needed(1),
        )
        .await;
        assert_that!(refreshed).is_false();

        gate.release();
        within_test_timeout(
            "the detached refresh must terminate after the gate opens",
            discovery.wait_for_completion(2),
        )
        .await;
        assert_that!(discovery.decoding_keys().exact("key-b")).is_some();
    }

    #[tokio::test]
    async fn refresh_continues_when_the_caller_that_started_it_is_cancelled() {
        let provider = MockOidcServer::start().await;
        provider.set_jwks(vec![key_a()]).await;
        let discovery = Arc::new(
            discovery_against(&provider, Arc::new(SystemClock), RefreshPolicy::default()).await,
        );
        let gate = provider.set_gated_jwks(vec![key_b()]).await;
        let waiting_caller = {
            let discovery = discovery.clone();
            tokio::spawn(async move { discovery.refresh_if_needed(1).await })
        };
        provider.wait_for_jwks_requests(2).await;

        waiting_caller.abort();
        gate.release();
        within_test_timeout(
            "the detached refresh must terminate after its caller was cancelled",
            discovery.wait_for_completion(2),
        )
        .await;

        assert_that!(discovery.decoding_keys().exact("key-b")).is_some();
        assert_that!(provider.discovery_requests()).is_equal_to(2);
        assert_that!(provider.jwks_requests()).is_equal_to(2);
    }

    #[tokio::test]
    async fn dropping_discovery_cancels_its_in_flight_operation() {
        let endpoint = fixture_endpoint();
        let operation_dropped = Arc::new(AtomicBool::new(false));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let started_tx = Arc::new(Mutex::new(Some(started_tx)));
        let op = {
            let operation_dropped = operation_dropped.clone();
            Arc::new(move |_endpoint, _request| {
                let operation_dropped = operation_dropped.clone();
                let started_tx = started_tx.clone();
                Box::pin(async move {
                    let _drop_flag = DropFlag(operation_dropped);
                    started_tx
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .take()
                        .expect("the initial operation must own the start signal")
                        .send(())
                        .expect("the test must still be waiting for the operation");
                    std::future::pending().await
                }) as futures::future::BoxFuture<'static, super::DiscoveryResult>
            })
        };
        let discovery = Discovery::new(
            endpoint,
            op,
            uuid::Uuid::from_u128(1),
            Arc::new(SystemClock),
            RefreshPolicy::default(),
        );
        started_rx
            .await
            .expect("the initial discovery operation must start");

        drop(discovery);

        wait_until(
            "dropping the last discovery owner must cancel the in-flight operation",
            || operation_dropped.load(Ordering::SeqCst),
        )
        .await;
    }

    #[test]
    fn refresh_recovers_after_its_originating_runtime_is_destroyed() {
        let endpoint = fixture_endpoint();
        let data = Arc::new(static_discovered_data());
        let clock = ManualClock::at_validation_time();
        let requests = Arc::new(AtomicUsize::new(0));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let started_tx = Arc::new(Mutex::new(Some(started_tx)));
        let op = {
            let data = data.clone();
            let requests = requests.clone();
            let started_tx = started_tx.clone();
            Arc::new(move |_endpoint, _request| {
                let data = data.clone();
                let request = requests.fetch_add(1, Ordering::SeqCst);
                let started_tx = started_tx.clone();
                Box::pin(async move {
                    if request == 0 {
                        started_tx
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .take()
                            .expect("the first request must own the start signal")
                            .send(())
                            .expect("the test must still be waiting for the first request");
                        return std::future::pending().await;
                    }
                    Ok(data)
                }) as futures::future::BoxFuture<'static, super::DiscoveryResult>
            })
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the first test runtime must build");
        let discovery = runtime.block_on(async {
            let discovery = Discovery::new(
                endpoint,
                op,
                uuid::Uuid::from_u128(1),
                clock.clone(),
                refresh_policy_without_jitter(),
            );
            started_rx
                .await
                .expect("the first discovery must signal that it started");
            discovery
        });

        drop(runtime);

        // Destroying the runtime says nothing about the provider, so the cancelled discovery is
        // neither booked as a failure nor backed off, and the next runtime may retry immediately.
        assert_that!(discovery.snapshot()).matches(partial!(RefreshStateSnapshot {
            pending: IsFalse,
            generation: eq(1),
            consecutive_failures: eq(0),
            last_error_at: IsNone,
            next_refresh_at: IsNone,
            ..
        }));

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the second test runtime must build");
        assert_that!(runtime.block_on(discovery.refresh_if_needed(1))).is_true();

        assert_that!(requests.load(Ordering::SeqCst)).is_equal_to(2);
        assert_that!(discovery.is_operational()).is_true();
        assert_that!(discovery.snapshot()).matches(partial!(RefreshStateSnapshot {
            pending: IsFalse,
            generation: eq(2),
            consecutive_failures: eq(0),
            ..
        }));
    }

    /// Tokio drops a task spawned during runtime shutdown synchronously, inside `spawn`. Its
    /// dispatch guard then locks the refresh state, so spawning while holding that lock would
    /// deadlock the worker.
    ///
    /// This relies on `refresh_if_needed` reading the monotonic clock exactly once, right before
    /// it locks the refresh state.
    #[test]
    fn runtime_shutdown_during_on_demand_spawn_does_not_deadlock_the_worker() {
        let mut discovery = Discovery::resolved(fixture_endpoint(), static_discovered_data());
        let (clock_blocked_tx, clock_blocked_rx) = mpsc::sync_channel(1);
        let (release_clock_tx, release_clock_rx) = mpsc::sync_channel(1);
        discovery.clock = Arc::new(BlockingMonotonicClock {
            inner: ManualClock::at_validation_time(),
            block_next: AtomicBool::new(true),
            blocked: Mutex::new(Some(clock_blocked_tx)),
            release: Mutex::new(release_clock_rx),
        });
        discovery.policy = refresh_policy_without_jitter();
        let discovery = Arc::new(discovery);

        let (worker_stopped_tx, worker_stopped_rx) = mpsc::sync_channel(1);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .on_thread_stop(move || {
                let _ = worker_stopped_tx.try_send(());
            })
            .build()
            .expect("the test runtime must build");
        let (result_tx, result_rx) = mpsc::sync_channel(1);
        let discovery_for_refresh = discovery.clone();
        let _refresh = runtime.spawn(async move {
            result_tx
                .send(discovery_for_refresh.refresh_if_needed(1).await)
                .expect("the test must still be waiting for the refresh result");
        });
        clock_blocked_rx
            .recv_timeout(TEST_TIMEOUT)
            .expect("the refresh must block immediately before taking the refresh-state lock");

        runtime.shutdown_background();
        worker_stopped_rx
            .recv_timeout(TEST_TIMEOUT)
            .expect("an idle runtime worker must close the owned-task list during shutdown");
        release_clock_tx
            .send(())
            .expect("the blocked refresh must still be waiting for release");

        let refreshed = result_rx
            .recv_timeout(TEST_TIMEOUT)
            .expect("runtime shutdown must not deadlock the refresh worker");
        assert_that!(refreshed).is_true();
        assert_that!(discovery.snapshot()).matches(partial!(RefreshStateSnapshot {
            pending: IsFalse,
            generation: eq(2),
            consecutive_failures: eq(0),
            last_error_at: IsNone,
            next_refresh_at: IsNone,
            ..
        }));
    }

    #[tokio::test]
    async fn panicking_discovery_terminates_waiters_and_keeps_stale_data() {
        let mut discovery = Discovery::resolved(fixture_endpoint(), static_discovered_data());
        discovery.op =
            Arc::new(|_endpoint, _request| Box::pin(async { panic!("requested discovery panic") }));

        let initial_keys = discovery.decoding_keys();
        assert_that!(initial_keys.generation()).is_equal_to(1);
        assert_that!(initial_keys.all().count()).is_equal_to(1);

        // The resolved test discovery starts at generation 1; observing that generation forces a
        // new dispatch.
        within_test_timeout(
            "a panicking discovery must still terminate its waiters",
            discovery.refresh_if_needed(1),
        )
        .await;

        assert_that!(discovery.is_operational()).is_true();
        assert_that!(discovery.snapshot()).matches(partial!(RefreshStateSnapshot {
            pending: IsFalse,
            generation: eq(2),
            consecutive_failures: eq(1),
            last_error_at: IsSome,
            next_refresh_at: IsSome,
            ..
        }));

        let refreshed_keys = discovery.decoding_keys();
        assert_that!(refreshed_keys.generation()).is_equal_to(2);
        assert_that!(refreshed_keys.all().count()).is_equal_to(1);
    }
}
