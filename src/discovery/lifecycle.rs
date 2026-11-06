//! Single-flight discovery, background key refreshes, refresh timing state, cached generations,
//! key expiry, and health reporting.
//!
//! A completed transition publishes its key data, generation, and confirmation time together
//! before waking waiters.
//! The lifecycle drives any supplied [`DiscoveryOp`] and does not depend on [`super::provider`].

use std::{
    fmt::Debug,
    ops::Deref,
    sync::{Arc, Mutex, PoisonError, Weak},
    time::{Duration, Instant},
};

use futures::{FutureExt, future::Either};
use time::OffsetDateTime;
use tokio::{sync::watch, task::AbortHandle};

use crate::{clock::Clock, error::AuthError};

use super::{
    DecodingKeys, DiscoveredData, DiscoveryConfig, DiscoveryKind, DiscoveryOp, DiscoveryRequest,
    DiscoveryResult, OidcDiscoveryEndpoint,
};

#[derive(Debug)]
enum RefreshError {
    Discovery(AuthError),
    NoUsableDecodingKeys,
    Panicked,
    TimedOut(Duration),
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
            RefreshError::TimedOut(timeout) => {
                format!("The discovery did not finish within {timeout:?}")
            }
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
    /// Whether at least one usable decoding key is available and may be used. Keys that
    /// [`ExpiredKeys`](crate::instance::ExpiredKeys) rejects do not count.
    pub is_operational: bool,
    /// Time since the last successful discovery completed, which is the age of the cached keys, by
    /// whichever of the monotonic and the wall clock reports more.
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

/// What the lifecycle publishes after every terminated discovery attempt.
#[derive(Debug, Clone, Default)]
struct Published {
    /// The number of terminated discovery attempts, successful or not.
    generation: usize,
    /// The data of the latest successful discovery that returned usable decoding keys.
    data: Option<Arc<DiscoveredData>>,
    /// When the provider last confirmed `data` through a successful discovery. Failed and
    /// cancelled attempts leave it untouched, so stale data stays stale.
    confirmed_at: Option<Instant>,
    /// The wall-clock time of `confirmed_at`. Monotonic time may stop while the system is
    /// suspended, wall-clock time does not, so the key age is measured on both.
    confirmed_at_utc: Option<OffsetDateTime>,
}

impl Published {
    /// The age of the keys at `now`, by whichever clock reports more, so that time the system spent
    /// suspended counts as well. `None` without keys.
    fn key_age(&self, now: Instant, now_utc: OffsetDateTime) -> Option<Duration> {
        let monotonic = now.saturating_duration_since(self.confirmed_at?);
        let wall_clock = self
            .confirmed_at_utc
            .and_then(|confirmed_at_utc| Duration::try_from(now_utc - confirmed_at_utc).ok())
            .unwrap_or(Duration::ZERO);
        Some(monotonic.max(wall_clock))
    }
}

/// The outcome of asking for a refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefreshStart {
    /// A discovery already terminated after the observed generation.
    Newer,
    /// No discovery is running, and the cooldown or failure backoff forbids starting one.
    Deferred,
    /// A discovery is running now, started by this call or joined.
    Running {
        /// Whether the most recent terminated attempt failed.
        latest_attempt_failed: bool,
        /// How long a request may still wait for the running discovery: what remains of
        /// `max_refresh_wait`, counted from when it started. Zero for a discovery that already
        /// took longer than any request may wait, for example because the provider stopped
        /// answering.
        wait: Duration,
    },
}

/// What the background refresh task does next.
enum BackgroundStep {
    /// Wait for the running discovery to terminate.
    AwaitCompletion {
        snapshots: watch::Receiver<Published>,
        observed_generation: usize,
    },
    /// Sleep until the next refresh is due, or `None` for never, waking early when any discovery
    /// terminates.
    Sleep {
        deadline: Option<Instant>,
        snapshots: watch::Receiver<Published>,
    },
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

    fn begin(&mut self, now: Instant) {
        self.pending = true;
        self.last_attempted_at = Some(now);
    }

    /// Records the outcome of a completed discovery and returns the data to publish in place of
    /// the current data, which is only the case after a successful discovery with usable keys.
    fn finish(
        &mut self,
        request: &DiscoveryRequest,
        result: DiscoveryResult,
        now: Instant,
        instance_id: uuid::Uuid,
        config: &DiscoveryConfig,
    ) -> Option<Arc<DiscoveredData>> {
        match result {
            Ok(data) if !data.has_usable_decoding_keys() => {
                self.record_failure(
                    request,
                    RefreshError::NoUsableDecodingKeys,
                    now,
                    instance_id,
                    config,
                );
                None
            }
            Ok(data) => {
                self.last_successful_at = Some(now);
                self.last_error = None;
                self.consecutive_failures = 0;
                self.next_refresh_at = match request.kind {
                    DiscoveryKind::Initial => None,
                    DiscoveryKind::Scheduled
                    | DiscoveryKind::Overdue
                    | DiscoveryKind::NoKeys
                    | DiscoveryKind::UnknownKid
                    | DiscoveryKind::KeysExpired => {
                        now.checked_add(config.success_delay(instance_id, request.attempt))
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
                    config,
                );
                None
            }
        }
    }

    fn record_failure(
        &mut self,
        request: &DiscoveryRequest,
        error: RefreshError,
        now: Instant,
        instance_id: uuid::Uuid,
        config: &DiscoveryConfig,
    ) {
        // Update the state before logging: a panicking `tracing` layer must not skip the backoff.
        let message = error.message();
        let panicked = matches!(error, RefreshError::Panicked);
        self.last_error = Some((now, error));
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.next_refresh_at = now.checked_add(config.failure_delay(
            instance_id,
            self.consecutive_failures,
            request.attempt,
        ));
        if panicked {
            tracing::error!(
                error = %message,
                "OIDC refresh panicked. The previous cache state is kept."
            );
        } else {
            tracing::warn!(
                error = %message,
                "OIDC refresh failed. The previous cache state is kept."
            );
        }
    }
}

enum DispatchOutcome {
    Completed(DiscoveryResult),
    Panicked,
    TimedOut(Duration),
    Cancelled,
}

/// Completes the refresh state transition even when Tokio drops the detached task before its
/// operation resolves, such as when the task's originating runtime is destroyed.
struct DispatchGuard {
    request: DiscoveryRequest,
    refresh_state: Arc<Mutex<RefreshState>>,
    published: watch::Sender<Published>,
    clock: Arc<dyn Clock>,
    instance_id: uuid::Uuid,
    config: DiscoveryConfig,
    armed: bool,
}

impl DispatchGuard {
    fn new(
        request: DiscoveryRequest,
        refresh_state: Arc<Mutex<RefreshState>>,
        published: watch::Sender<Published>,
        clock: Arc<dyn Clock>,
        instance_id: uuid::Uuid,
        config: DiscoveryConfig,
    ) -> Self {
        Self {
            request,
            refresh_state,
            published,
            clock,
            instance_id,
            config,
            armed: true,
        }
    }

    fn complete(mut self, outcome: DispatchOutcome) {
        // Disarm first: `publish` completes the transition even if recording the outcome panics,
        // so Drop must not repeat it.
        self.armed = false;
        if let Err(panic) = self.publish(outcome) {
            std::panic::resume_unwind(panic);
        }
    }

    /// Records `outcome`, clears the single-flight marker, and publishes the next generation.
    ///
    /// Recording logs and reads the clock, either of which may panic, for example in a `tracing`
    /// layer. The transition completes regardless, because a `pending` marker that is never
    /// cleared would block every later refresh. Such a panic is returned for the caller to resume.
    fn publish(&self, outcome: DispatchOutcome) -> std::thread::Result<()> {
        let mut state = self
            .refresh_state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let recorded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let now = self.clock.now_monotonic();
            self.record(&mut state, outcome, now)
                .map(|data| (data, now, self.clock.now_utc()))
        }));
        state.pending = false;
        let confirmed = recorded.as_ref().ok().cloned().flatten();
        self.published.send_modify(|published| {
            published.generation += 1;
            if let Some((data, confirmed_at, confirmed_at_utc)) = confirmed {
                published.data = Some(data);
                published.confirmed_at = Some(confirmed_at);
                published.confirmed_at_utc = Some(confirmed_at_utc);
            }
        });
        recorded.map(|_confirmed| ())
    }

    /// Records `outcome` in `state` and returns the data to publish in place of the current data,
    /// which is only the case after a successful discovery with usable keys.
    fn record(
        &self,
        state: &mut RefreshState,
        outcome: DispatchOutcome,
        now: Instant,
    ) -> Option<Arc<DiscoveredData>> {
        let failure = match outcome {
            DispatchOutcome::Completed(result) => {
                return state.finish(&self.request, result, now, self.instance_id, &self.config);
            }
            DispatchOutcome::Panicked => RefreshError::Panicked,
            DispatchOutcome::TimedOut(timeout) => RefreshError::TimedOut(timeout),
            // The task was dropped before its operation finished: its runtime shut down, the last
            // lifecycle owner aborted it, or it could not be spawned outside a runtime. None of
            // this says anything about the provider. Neither record a failure nor back off, so
            // that a later runtime may retry immediately.
            DispatchOutcome::Cancelled => {
                tracing::debug!("OIDC refresh was cancelled. The previous cache state is kept.");
                return None;
            }
        };
        state.record_failure(&self.request, failure, now, self.instance_id, &self.config);
        None
    }
}

impl Drop for DispatchGuard {
    fn drop(&mut self) {
        if self.armed {
            // Panicking in Drop could abort the process. The transition completed regardless.
            let _recorded = self.publish(DispatchOutcome::Cancelled);
        }
    }
}

/// Owns the discovery lifecycle: the cached provider data, the background refresh task,
/// single-flight refreshes with cooldown/backoff, key expiry, and the completion signal callers
/// wait on.
///
/// Dropping it stops the background task and aborts a running discovery.
pub(crate) struct Discovery {
    shared: Arc<Shared>,
    /// Stops the background refresh task, which only holds a [`Weak`] reference to `shared`.
    background_abort: Option<AbortHandle>,
}

/// The lifecycle state shared with the background refresh task.
pub(crate) struct Shared {
    instance_id: uuid::Uuid,
    endpoint: OidcDiscoveryEndpoint,
    op: DiscoveryOp,
    refresh_state: Arc<Mutex<RefreshState>>,
    /// Atomically publishes each terminated discovery's generation, resulting cached data, and
    /// that data's confirmation time, and doubles as the completion signal for waiters.
    published: watch::Sender<Published>,
    /// Cancels the detached operation when the last owner is dropped. A completed operation may
    /// leave a stale handle here until the next spawn. Aborting it is harmless.
    in_flight_abort: Mutex<Option<AbortHandle>>,
    clock: Arc<dyn Clock>,
    config: DiscoveryConfig,
}

impl Debug for Discovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Discovery")
            .field("instance_id", &self.instance_id)
            .field("endpoint", &self.endpoint)
            .field("generation", &self.published.borrow().generation)
            .finish_non_exhaustive()
    }
}

impl Deref for Discovery {
    type Target = Shared;

    fn deref(&self) -> &Shared {
        &self.shared
    }
}

impl Discovery {
    /// Creates the discovery lifecycle, immediately spawns the initial discovery, and starts the
    /// background refresh task unless the configuration disables it.
    pub(crate) fn new(
        endpoint: OidcDiscoveryEndpoint,
        op: DiscoveryOp,
        instance_id: uuid::Uuid,
        clock: Arc<dyn Clock>,
        config: DiscoveryConfig,
    ) -> Self {
        let shared = Arc::new(Shared {
            instance_id,
            endpoint,
            op,
            refresh_state: Arc::new(Mutex::new(RefreshState::initial(clock.now_monotonic()))),
            published: watch::Sender::new(Published::default()),
            in_flight_abort: Mutex::new(None),
            clock,
            config,
        });
        shared.spawn(DiscoveryRequest {
            attempt: 1,
            kind: DiscoveryKind::Initial,
        });
        let background_abort = shared
            .config
            .background_refresh
            .then(|| tokio::spawn(run_background_refresh(Arc::downgrade(&shared))).abort_handle());
        Self {
            shared,
            background_abort,
        }
    }

    #[cfg(test)]
    pub(crate) fn resolved(endpoint: OidcDiscoveryEndpoint, data: DiscoveredData) -> Self {
        let clock: Arc<dyn Clock> = Arc::new(crate::clock::SystemClock);
        let now = clock.now_monotonic();
        Self {
            shared: Arc::new(Shared {
                instance_id: uuid::Uuid::now_v7(),
                endpoint,
                op: Arc::new(|_endpoint, _request| {
                    Box::pin(async { panic!("a resolved test discovery cannot re-discover") })
                }),
                refresh_state: Arc::new(Mutex::new(RefreshState::resolved(now))),
                published: watch::Sender::new(Published {
                    generation: 1,
                    data: Some(Arc::new(data)),
                    confirmed_at: Some(now),
                    confirmed_at_utc: Some(clock.now_utc()),
                }),
                in_flight_abort: Mutex::new(None),
                clock,
                config: DiscoveryConfig {
                    background_refresh: false,
                    ..DiscoveryConfig::default()
                },
            }),
            background_abort: None,
        }
    }

    /// Mutable access to the state of a lifecycle without a background task, for tests replacing
    /// its operation, clock, or configuration.
    #[cfg(test)]
    fn shared_mut(&mut self) -> &mut Shared {
        Arc::get_mut(&mut self.shared).expect("a resolved test discovery is not shared")
    }
}

impl Drop for Discovery {
    fn drop(&mut self) {
        if let Some(background_abort) = self.background_abort.take() {
            background_abort.abort();
        }
    }
}

/// The longest the background task sleeps before it checks again whether a refresh is due. Its
/// sleeps follow monotonic time, while keys also age with wall-clock time, which may jump ahead,
/// for example when the system resumes from suspension.
const WALL_CLOCK_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// Refreshes the keys of `shared` whenever they reach the configured `refresh_after`, retries
/// failed discoveries after their backoff, and ends once the lifecycle is dropped.
///
/// Holds a strong reference only while deciding the next step, never across an `await`, so that
/// it does not keep a dropped lifecycle alive.
async fn run_background_refresh(shared: Weak<Shared>) {
    loop {
        // Every iteration yields at least once. Without this, a discovery that a shutting-down
        // runtime drops inside `spawn` would publish its cancellation before the task awaits, and
        // the task would respawn it forever without ever giving the runtime a chance to stop it.
        tokio::task::yield_now().await;
        let (step, clock) = match shared.upgrade() {
            Some(shared) => (shared.background_step(), shared.clock.clone()),
            None => return,
        };
        match step {
            BackgroundStep::AwaitCompletion {
                mut snapshots,
                observed_generation,
            } => {
                while snapshots.borrow_and_update().generation <= observed_generation {
                    if snapshots.changed().await.is_err() {
                        return;
                    }
                }
            }
            BackgroundStep::Sleep {
                deadline,
                mut snapshots,
            } => {
                let sleep = match deadline {
                    Some(deadline) => clock.sleep_until(deadline),
                    None => Box::pin(std::future::pending()),
                };
                let changed = Box::pin(async move { snapshots.changed().await });
                if let Either::Right((Err(_closed), _sleep)) =
                    futures::future::select(sleep, changed).await
                {
                    return;
                }
            }
        }
    }
}

impl Shared {
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
            self.config.clone(),
        );
        let clock = self.clock.clone();
        let discovery_timeout = self.config.discovery_timeout;
        let abort_handle = tokio::spawn(async move {
            let operation = std::panic::AssertUnwindSafe(async move {
                operation(endpoint, operation_request).await
            })
            .catch_unwind();
            // Bounds the whole discovery, including retries, so that a provider that stops
            // answering cannot hold the single-flight marker forever.
            let timeout = match clock.now_monotonic().checked_add(discovery_timeout) {
                Some(deadline) => clock.sleep_until(deadline),
                None => Box::pin(std::future::pending()),
            };
            let outcome = match futures::future::select(Box::pin(operation), timeout).await {
                Either::Left((Ok(result), _timeout)) => DispatchOutcome::Completed(result),
                Either::Left((Err(_panic), _timeout)) => DispatchOutcome::Panicked,
                Either::Right(((), _operation)) => DispatchOutcome::TimedOut(discovery_timeout),
            };
            guard.complete(outcome);
        })
        .abort_handle();
        *in_flight_abort = Some(abort_handle);
    }

    /// Decides the background task's next step, starting a refresh if one is due.
    ///
    /// A refresh is due once the keys reach `refresh_after`, or immediately while no keys were
    /// discovered, but never before the cooldown or failure backoff ends.
    fn background_step(&self) -> BackgroundStep {
        let now = self.clock.now_monotonic();
        let now_utc = self.clock.now_utc();
        // Subscribed before reading the state, so that any later publication wakes the sleeper.
        let snapshots = self.published.subscribe();
        let (request, observed_generation) = {
            let mut state = self
                .refresh_state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let published = self.published.borrow();
            let generation = published.generation;
            if state.pending {
                return BackgroundStep::AwaitCompletion {
                    snapshots,
                    observed_generation: generation,
                };
            }
            // Due once the keys are `refresh_after` old by either clock.
            let due_at = match published.key_age(now, now_utc) {
                Some(age) => now.checked_add(self.config.refresh_after.saturating_sub(age)),
                None => Some(now),
            }
            .map(|due_at| {
                state
                    .next_refresh_at
                    .map_or(due_at, |next| next.max(due_at))
            });
            match due_at {
                Some(due_at) if now >= due_at => {}
                deadline => {
                    // Monotonic sleeps miss wall-clock jumps, for example after the system was
                    // suspended, so the task checks again at least this often.
                    let check_again_at = now.checked_add(WALL_CLOCK_CHECK_INTERVAL);
                    let deadline = match (deadline, check_again_at) {
                        (Some(deadline), Some(check_again_at)) => {
                            Some(deadline.min(check_again_at))
                        }
                        (deadline, check_again_at) => deadline.or(check_again_at),
                    };
                    return BackgroundStep::Sleep {
                        deadline,
                        snapshots,
                    };
                }
            }
            drop(published);
            state.begin(now);
            let request = DiscoveryRequest {
                attempt: generation.saturating_add(1),
                kind: DiscoveryKind::Scheduled,
            };
            (request, generation)
        };
        // Spawn outside the refresh-state lock and the published snapshot: during runtime
        // shutdown, Tokio can drop the new task synchronously here, and its dispatch guard then
        // needs to re-lock that state and publish.
        self.spawn(request);
        BackgroundStep::AwaitCompletion {
            snapshots,
            observed_generation,
        }
    }

    /// Starts or joins one shared refresh and waits for it, unless a refresh already completed
    /// after `observed_generation` or the discovery configuration's cooldown/backoff still applies.
    ///
    /// The wait is capped by the configured `max_refresh_wait`, so a stalled provider does not
    /// block requests indefinitely. The refresh itself continues independently of this waiter
    /// while the lifecycle remains owned.
    ///
    /// Returns whether a discovery terminated after `observed_generation`, meaning the cached data
    /// may have changed and a retry is worthwhile. A terminated discovery may also have failed or
    /// been dropped and left the data as it was, so `true` does not guarantee new keys.
    ///
    /// `kind` records why the refresh is needed, if this call starts it.
    pub(crate) async fn refresh_if_needed(
        &self,
        observed_generation: usize,
        kind: DiscoveryKind,
    ) -> bool {
        let now = self.clock.now_monotonic();
        match self.start_or_join_refresh(observed_generation, now, kind) {
            RefreshStart::Newer => true,
            RefreshStart::Deferred => false,
            RefreshStart::Running { wait, .. } => {
                self.wait_for_refresh(observed_generation, wait).await
            }
        }
    }

    /// Like [`Self::refresh_if_needed`] for keys that are rejected because they expired, but only
    /// waits while the most recent attempt succeeded. Keys are only rejected while refreshes fail,
    /// or when the background task fell behind. Waiting during a provider outage would merely
    /// delay the rejection.
    pub(crate) async fn refresh_expired_keys(&self, observed_generation: usize) -> bool {
        let now = self.clock.now_monotonic();
        match self.start_or_join_refresh(observed_generation, now, DiscoveryKind::KeysExpired) {
            RefreshStart::Newer => true,
            RefreshStart::Running {
                latest_attempt_failed: false,
                wait,
            } => self.wait_for_refresh(observed_generation, wait).await,
            RefreshStart::Deferred | RefreshStart::Running { .. } => false,
        }
    }

    /// Starts a refresh without waiting for it once the cached keys reach `refresh_after`. This
    /// backs up the background task, for example when it is disabled or could not keep up.
    ///
    /// Leaves expired keys to [`Self::refresh_expired_keys`], which validation calls next, so
    /// that the refresh is recorded as caused by the expiry.
    pub(crate) fn refresh_if_stale(&self) {
        let now = self.clock.now_monotonic();
        let now_utc = self.clock.now_utc();
        let observed_generation = {
            let published = self.published.borrow();
            if self.is_rejected(&published, now, now_utc) {
                return;
            }
            match published.key_age(now, now_utc) {
                Some(age) if age >= self.config.refresh_after => published.generation,
                _ => return,
            }
        };
        self.start_or_join_refresh(observed_generation, now, DiscoveryKind::Overdue);
    }

    fn start_or_join_refresh(
        &self,
        observed_generation: usize,
        now: Instant,
        kind: DiscoveryKind,
    ) -> RefreshStart {
        let (request, latest_attempt_failed) = {
            let mut state = self
                .refresh_state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let generation = self.published.borrow().generation;
            if generation > observed_generation {
                return RefreshStart::Newer;
            }
            let latest_attempt_failed = state.consecutive_failures > 0;
            if state.pending {
                let waited = state
                    .last_attempted_at
                    .map_or(Duration::ZERO, |started_at| {
                        now.saturating_duration_since(started_at)
                    });
                return RefreshStart::Running {
                    latest_attempt_failed,
                    wait: self.config.max_refresh_wait.saturating_sub(waited),
                };
            }
            if state.next_refresh_at.is_some_and(|deadline| now < deadline) {
                return RefreshStart::Deferred;
            }
            let request = DiscoveryRequest {
                attempt: generation.saturating_add(1),
                kind,
            };
            state.begin(now);
            (request, latest_attempt_failed)
        };
        // Spawn outside the refresh-state lock: during runtime shutdown, Tokio can drop the new
        // task synchronously here, and the dispatch guard then needs to re-lock that state.
        self.spawn(request);
        RefreshStart::Running {
            latest_attempt_failed,
            wait: self.config.max_refresh_wait,
        }
    }

    /// Waits, at most `wait`, until a discovery terminated after `observed_generation`, and
    /// returns whether one did.
    async fn wait_for_refresh(&self, observed_generation: usize, wait: Duration) -> bool {
        if wait.is_zero() {
            return self.published.borrow().generation > observed_generation;
        }
        let wait_for_refresh = async {
            let mut snapshots = self.published.subscribe();
            while snapshots.borrow_and_update().generation <= observed_generation {
                if snapshots.changed().await.is_err() {
                    return;
                }
            }
        };
        if tokio::time::timeout(wait, wait_for_refresh).await.is_err() {
            tracing::warn!(
                "Timed out waiting for a shared OIDC discovery refresh. Validation continues with the current key set."
            );
        }
        self.published.borrow().generation > observed_generation
    }

    /// Whether `ExpiredKeys` rejects the keys of `published` at `now`.
    fn is_rejected(&self, published: &Published, now: Instant, now_utc: OffsetDateTime) -> bool {
        match (published.key_age(now, now_utc), self.config.trusted_for()) {
            (Some(age), Some(trusted_for)) => age >= trusted_for,
            _ => false,
        }
    }

    /// Returns true while discovery has produced at least one usable decoding key that is not
    /// rejected.
    pub(crate) fn is_operational(&self) -> bool {
        self.unavailability().is_none()
    }

    /// Why no token can currently be verified, or `None` while usable keys are available.
    pub(crate) fn unavailability(&self) -> Option<AuthError> {
        let now = self.clock.now_monotonic();
        let now_utc = self.clock.now_utc();
        {
            let published = self.published.borrow();
            if published
                .data
                .as_ref()
                .is_some_and(|data| data.has_usable_decoding_keys())
            {
                return self
                    .is_rejected(&published, now, now_utc)
                    .then_some(AuthError::DecodingKeysExpired);
            }
        }
        // Released the snapshot first: reading the last error takes the refresh-state lock, which
        // publishing holds while it updates the snapshot.
        Some(
            self.last_discovery_error()
                .unwrap_or(AuthError::NoOidcDiscovery),
        )
    }

    /// The keys validation may currently use. Rejected keys are withheld.
    pub(crate) fn decoding_keys(&self) -> DecodingKeys {
        let now = self.clock.now_monotonic();
        let now_utc = self.clock.now_utc();
        let published = self.published.borrow();
        if self.is_rejected(&published, now, now_utc) {
            DecodingKeys::expired(published.generation)
        } else {
            DecodingKeys::new(published.data.clone(), published.generation)
        }
    }

    /// Waits until at least `expected_completion` discovery attempts have terminated,
    /// successfully or not.
    pub(crate) async fn wait_for_completion(&self, expected_completion: usize) {
        let mut snapshots = self.published.subscribe();
        while snapshots.borrow_and_update().generation < expected_completion {
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
            Some((_at, RefreshError::TimedOut(timeout))) => {
                Some(AuthError::DiscoveryTimedOut { timeout: *timeout })
            }
            Some((_, RefreshError::Panicked)) | None => None,
        }
    }

    pub(crate) fn operational_status(&self) -> OperationalStatus {
        let now = self.clock.now_monotonic();
        let key_age = self.published.borrow().key_age(now, self.clock.now_utc());
        let is_operational = self.is_operational();
        let state = self
            .refresh_state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        OperationalStatus {
            is_operational,
            time_since_last_success: key_age,
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
            generation: self.published.borrow().generation,
        }
    }
}

impl Drop for Shared {
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
        discovery::{ExpiredKeys, default_discovery_op},
        error::AuthError,
        test_support::{
            CapturedLogs, ManualClock, MockOidcServer, RSA_KEY_A, RSA_KEY_B, TEST_REALM,
            TEST_TIMEOUT, discovery_config_without_jitter, static_discovered_data,
            test_http_client, test_server_url, validation_time, wait_until, within_test_timeout,
        },
    };

    use super::{
        Discovery, DiscoveryConfig, DiscoveryKind, OidcDiscoveryEndpoint, RefreshStateSnapshot,
    };

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
        config: DiscoveryConfig,
    ) -> Discovery {
        let server = provider.server_url();
        let endpoint = OidcDiscoveryEndpoint::new(&server, provider.realm());
        let op = default_discovery_op(
            test_http_client(),
            uuid::Uuid::from_u128(1),
            server.to_string(),
            provider.realm().to_owned(),
            1,
            Duration::ZERO,
        );
        let discovery = Discovery::new(endpoint, op, uuid::Uuid::from_u128(1), clock, config);
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

        fn sleep_until(
            &self,
            deadline: std::time::Instant,
        ) -> futures::future::BoxFuture<'static, ()> {
            self.inner.sleep_until(deadline)
        }
    }

    /// The discovery endpoint of the offline fixture realm, which is never contacted.
    fn fixture_endpoint() -> OidcDiscoveryEndpoint {
        OidcDiscoveryEndpoint::new(&test_server_url(), TEST_REALM)
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
            discovery_against(&provider, clock.clone(), discovery_config_without_jitter()).await;

        // Generation 1 is the initial discovery; observing it starts one on-demand refresh.
        assert_that!(
            discovery
                .refresh_if_needed(1, DiscoveryKind::UnknownKid)
                .await
        )
        .is_true();
        assert_that!(provider.discovery_requests()).is_equal_to(2);

        // The success cooldown blocks further refreshes up to its exact deadline.
        clock.advance(time::Duration::milliseconds(4_999));
        assert_that!(
            discovery
                .refresh_if_needed(2, DiscoveryKind::UnknownKid)
                .await
        )
        .is_false();
        assert_that!(provider.discovery_requests()).is_equal_to(2);

        clock.advance(time::Duration::milliseconds(1));
        assert_that!(
            discovery
                .refresh_if_needed(2, DiscoveryKind::UnknownKid)
                .await
        )
        .is_true();
        assert_that!(provider.discovery_requests()).is_equal_to(3);
        assert_that!(provider.jwks_requests()).is_equal_to(3);
    }

    #[tokio::test]
    async fn failed_refresh_backoff_grows_and_resets_after_success() {
        let provider = MockOidcServer::start().await;
        provider.set_jwks(vec![key_a()]).await;
        let clock = ManualClock::at_validation_time();
        let discovery =
            discovery_against(&provider, clock.clone(), discovery_config_without_jitter()).await;
        provider.make_discovery_unavailable().await;

        // A failed refresh (one request plus one retry) starts the 1s backoff.
        // It still publishes a new generation, so the call reports one.
        assert_that!(
            discovery
                .refresh_if_needed(1, DiscoveryKind::UnknownKid)
                .await
        )
        .is_true();
        assert_that!(discovery.snapshot().consecutive_failures).is_equal_to(1);
        assert_that!(provider.discovery_requests()).is_equal_to(3);
        clock.advance(time::Duration::milliseconds(999));
        assert_that!(
            discovery
                .refresh_if_needed(2, DiscoveryKind::UnknownKid)
                .await
        )
        .is_false();
        assert_that!(provider.discovery_requests()).is_equal_to(3);

        // The second failure doubles the backoff.
        clock.advance(time::Duration::milliseconds(1));
        assert_that!(
            discovery
                .refresh_if_needed(2, DiscoveryKind::UnknownKid)
                .await
        )
        .is_true();
        assert_that!(discovery.snapshot().consecutive_failures).is_equal_to(2);
        assert_that!(provider.discovery_requests()).is_equal_to(5);

        provider.restore_discovery_response().await;
        clock.advance(time::Duration::milliseconds(1_999));
        assert_that!(
            discovery
                .refresh_if_needed(3, DiscoveryKind::UnknownKid)
                .await
        )
        .is_false();
        assert_that!(provider.discovery_requests()).is_equal_to(5);

        // A success at the exact backoff deadline ends the failure streak.
        clock.advance(time::Duration::milliseconds(1));
        assert_that!(
            discovery
                .refresh_if_needed(3, DiscoveryKind::UnknownKid)
                .await
        )
        .is_true();
        assert_that!(provider.discovery_requests()).is_equal_to(6);
        assert_that!(discovery.snapshot().consecutive_failures).is_equal_to(0);
    }

    /// [`discovery_config_without_jitter`] with the background refresh task, and keys handled as
    /// `expired_keys` prescribes.
    fn background_config(expired_keys: ExpiredKeys) -> DiscoveryConfig {
        DiscoveryConfig {
            background_refresh: true,
            expired_keys,
            ..discovery_config_without_jitter()
        }
    }

    /// [`discovery_config_without_jitter`], refreshing only on request, with keys handled as
    /// `expired_keys` prescribes.
    fn request_driven_config(expired_keys: ExpiredKeys) -> DiscoveryConfig {
        DiscoveryConfig {
            expired_keys,
            ..discovery_config_without_jitter()
        }
    }

    /// Lets the other tasks of the current-thread test runtime run until they wait for something,
    /// so that a test can assert what they did not do. The background task starts a discovery
    /// synchronously, so `pending` reflects any discovery it started.
    async fn let_tasks_run() {
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
    }

    /// Asserts that no discovery started since `snapshot` was taken.
    fn assert_no_discovery_started_since(discovery: &Discovery, snapshot: &RefreshStateSnapshot) {
        assert_that!(discovery.snapshot()).matches(partial!(RefreshStateSnapshot {
            pending: IsFalse,
            last_attempted_at: eq(snapshot.last_attempted_at),
            generation: eq(snapshot.generation),
            ..
        }));
    }

    #[tokio::test]
    async fn background_task_refreshes_keys_at_refresh_after_without_requests() {
        let logs = CapturedLogs::default();
        let _capture = logs.capture();
        let provider = MockOidcServer::start().await;
        provider.set_jwks(vec![key_a()]).await;
        let clock = ManualClock::at_validation_time();
        let discovery = discovery_against(
            &provider,
            clock.clone(),
            background_config(ExpiredKeys::default()),
        )
        .await;
        provider.set_jwks(vec![key_b()]).await;

        let before = discovery.snapshot();
        clock.advance(time::Duration::minutes(4) - time::Duration::milliseconds(1));
        let_tasks_run().await;
        assert_no_discovery_started_since(&discovery, &before);

        clock.advance(time::Duration::milliseconds(1));
        within_test_timeout(
            "the background task must refresh once the keys reach refresh_after",
            discovery.wait_for_completion(2),
        )
        .await;
        let keys = discovery.decoding_keys();
        assert_that!(keys.exact("key-a").is_none()).is_true();
        assert_that!(keys.exact("key-b")).is_some();
        assert_that!(logs.contents()).contains("discovery_kind=Scheduled");

        // The refresh confirmed the keys again, so the next one is due four minutes later.
        let_tasks_run().await;
        let before = discovery.snapshot();
        clock.advance(time::Duration::minutes(4) - time::Duration::milliseconds(1));
        let_tasks_run().await;
        assert_no_discovery_started_since(&discovery, &before);
        clock.advance(time::Duration::milliseconds(1));
        within_test_timeout(
            "the background task must keep refreshing",
            discovery.wait_for_completion(3),
        )
        .await;
        assert_that!(provider.discovery_requests()).is_equal_to(3);
    }

    #[tokio::test]
    async fn background_task_retries_a_failed_initial_discovery_without_requests() {
        let provider = MockOidcServer::start().await;
        provider.set_jwks(vec![key_a()]).await;
        provider.make_discovery_unavailable().await;
        let clock = ManualClock::at_validation_time();
        let discovery = discovery_against(
            &provider,
            clock.clone(),
            background_config(ExpiredKeys::default()),
        )
        .await;
        assert_that!(discovery.is_operational()).is_false();

        // The failure backoff applies to the background task, too.
        provider.restore_discovery_response().await;
        let_tasks_run().await;
        let before = discovery.snapshot();
        clock.advance(time::Duration::milliseconds(999));
        let_tasks_run().await;
        assert_no_discovery_started_since(&discovery, &before);

        clock.advance(time::Duration::milliseconds(1));
        within_test_timeout(
            "the background task must retry the initial discovery after its backoff",
            discovery.wait_for_completion(2),
        )
        .await;
        assert_that!(discovery.is_operational()).is_true();
    }

    #[tokio::test]
    async fn background_task_backs_off_after_a_failed_refresh_and_trust_keeps_keys_usable() {
        let provider = MockOidcServer::start().await;
        provider.set_jwks(vec![key_a()]).await;
        let clock = ManualClock::at_validation_time();
        let discovery = discovery_against(
            &provider,
            clock.clone(),
            background_config(ExpiredKeys::Trust),
        )
        .await;
        provider.make_discovery_unavailable().await;

        clock.advance(time::Duration::minutes(4));
        within_test_timeout(
            "the scheduled refresh must run and fail",
            discovery.wait_for_completion(2),
        )
        .await;
        assert_that!(discovery.snapshot().consecutive_failures).is_equal_to(1);

        // The failed scheduled refresh is retried after the failure backoff, not immediately.
        let_tasks_run().await;
        let before = discovery.snapshot();
        let requests_before = provider.discovery_requests();
        clock.advance(time::Duration::milliseconds(999));
        let_tasks_run().await;
        assert_no_discovery_started_since(&discovery, &before);
        assert_that!(provider.discovery_requests()).is_equal_to(requests_before);

        clock.advance(time::Duration::milliseconds(1));
        within_test_timeout(
            "the failed refresh must be retried after its backoff",
            discovery.wait_for_completion(3),
        )
        .await;
        assert_that!(discovery.snapshot().consecutive_failures).is_equal_to(2);

        // `Trust` keeps the keys usable through an outage of any length.
        clock.advance(time::Duration::days(365));
        within_test_timeout(
            "the background task must keep retrying during the outage",
            discovery.wait_for_completion(4),
        )
        .await;
        assert_that!(discovery.snapshot().consecutive_failures).is_equal_to(3);
        assert_that!(discovery.is_operational()).is_true();
        assert_that!(discovery.decoding_keys().exact("key-a")).is_some();
    }

    #[tokio::test]
    async fn dropping_discovery_stops_its_background_task_also_during_a_discovery() {
        for during_discovery in [false, true] {
            let provider = MockOidcServer::start().await;
            provider.set_jwks(vec![key_a()]).await;
            let clock = ManualClock::at_validation_time();
            let discovery = discovery_against(
                &provider,
                clock.clone(),
                background_config(ExpiredKeys::default()),
            )
            .await;
            let background_task = discovery
                .background_abort
                .clone()
                .expect("the discovery must run a background task");
            let _gate = if during_discovery {
                let gate = provider.set_gated_jwks(vec![key_b()]).await;
                clock.advance(time::Duration::minutes(4));
                provider.wait_for_jwks_requests(2).await;
                Some(gate)
            } else {
                None
            };

            drop(discovery);

            wait_until(
                "dropping the discovery must stop its background task",
                || background_task.is_finished(),
            )
            .await;
            let requests = provider.discovery_requests();
            clock.advance(time::Duration::minutes(10));
            let_tasks_run().await;
            assert_that!(provider.discovery_requests())
                .with_detail_message(format!("during discovery: {during_discovery}"))
                .is_equal_to(requests);
        }
    }

    #[test]
    fn background_task_does_not_spin_when_its_runtime_shuts_down() {
        let mut discovery = Discovery::resolved(fixture_endpoint(), static_discovered_data());
        let (clock_blocked_tx, clock_blocked_rx) = mpsc::sync_channel(1);
        let (release_clock_tx, release_clock_rx) = mpsc::sync_channel(1);
        discovery.shared_mut().clock = Arc::new(BlockingMonotonicClock {
            inner: ManualClock::at_validation_time(),
            block_next: AtomicBool::new(true),
            blocked: Mutex::new(Some(clock_blocked_tx)),
            release: Mutex::new(release_clock_rx),
        });
        // Every discovery is due immediately, so only a respawn loop could keep discovering.
        discovery.shared_mut().config = DiscoveryConfig {
            refresh_after: Duration::ZERO,
            ..discovery_config_without_jitter()
        };
        let (worker_stopped_tx, worker_stopped_rx) = mpsc::sync_channel(1);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .on_thread_stop(move || {
                let _ = worker_stopped_tx.try_send(());
            })
            .build()
            .expect("the test runtime must build");
        let _background = runtime.spawn(super::run_background_refresh(Arc::downgrade(
            &discovery.shared,
        )));
        clock_blocked_rx
            .recv_timeout(TEST_TIMEOUT)
            .expect("the background task must block while deciding its next step");

        // Shut the runtime down while the background task is about to spawn a discovery, which
        // the runtime then drops inside `spawn`.
        runtime.shutdown_background();
        worker_stopped_rx
            .recv_timeout(TEST_TIMEOUT)
            .expect("an idle runtime worker must close the owned-task list during shutdown");
        release_clock_tx
            .send(())
            .expect("the blocked background task must still be waiting for release");

        std::thread::sleep(Duration::from_millis(200));
        let settled = discovery.snapshot().generation;
        std::thread::sleep(Duration::from_millis(200));
        assert_that!(discovery.snapshot().generation)
            .with_detail_message("the background task must not respawn dropped discoveries")
            .is_equal_to(settled);
        assert_that!(settled).is_less_or_equal_to(2);
    }

    #[tokio::test]
    async fn keys_expire_as_expired_keys_prescribes() {
        let provider = MockOidcServer::start().await;
        provider.set_jwks(vec![key_a()]).await;
        for (expired_keys, still_used_for) in [
            (ExpiredKeys::Reject, Some(time::Duration::ZERO)),
            (
                ExpiredKeys::TrustFor(Duration::from_secs(60)),
                Some(time::Duration::minutes(1)),
            ),
            (ExpiredKeys::Trust, None),
        ] {
            // Without the background task, nothing refreshes the keys as they age.
            let clock = ManualClock::at_validation_time();
            let discovery = discovery_against(
                &provider,
                clock.clone(),
                request_driven_config(expired_keys),
            )
            .await;

            clock.advance(time::Duration::minutes(5) - time::Duration::milliseconds(1));
            if let Some(grace) = still_used_for {
                clock.advance(grace);
                assert_that!(discovery.is_operational())
                    .with_detail_message(format!("{expired_keys:?} before expiry"))
                    .is_true();
                assert_that!(discovery.decoding_keys().is_expired()).is_false();

                clock.advance(time::Duration::milliseconds(1));
                assert_that!(discovery.is_operational())
                    .with_detail_message(format!("{expired_keys:?} at expiry"))
                    .is_false();
                let keys = discovery.decoding_keys();
                assert_that!(keys.is_expired()).is_true();
                assert_that!(keys.all().count()).is_equal_to(0);
                assert_that!(discovery.operational_status().is_operational).is_false();
            } else {
                clock.advance(time::Duration::days(365));
                assert_that!(discovery.is_operational()).is_true();
                assert_that!(discovery.decoding_keys().exact("key-a")).is_some();
            }
        }
    }

    #[tokio::test]
    async fn expired_keys_get_a_waiting_refresh_only_while_the_latest_attempt_succeeded() {
        let provider = MockOidcServer::start().await;
        provider.set_jwks(vec![key_a()]).await;
        let clock = ManualClock::at_validation_time();
        let discovery = discovery_against(
            &provider,
            clock.clone(),
            request_driven_config(ExpiredKeys::Reject),
        )
        .await;

        // Keys that expired without a failed refresh get one, and the caller waits for it.
        clock.advance(time::Duration::minutes(5));
        assert_that!(discovery.decoding_keys().is_expired()).is_true();
        assert_that!(discovery.refresh_expired_keys(1).await).is_true();
        assert_that!(discovery.decoding_keys().exact("key-a")).is_some();

        // A failed attempt is still awaited, because the attempt before it succeeded.
        provider.make_discovery_unavailable().await;
        clock.advance(time::Duration::minutes(5));
        assert_that!(discovery.refresh_expired_keys(2).await).is_true();
        assert_that!(discovery.snapshot().consecutive_failures).is_equal_to(1);
        assert_that!(discovery.decoding_keys().is_expired()).is_true();

        // During the failure backoff, no refresh starts.
        let before = discovery.snapshot();
        let requests_before = provider.discovery_requests();
        assert_that!(discovery.refresh_expired_keys(3).await).is_false();
        assert_no_discovery_started_since(&discovery, &before);
        assert_that!(provider.discovery_requests()).is_equal_to(requests_before);

        // After the backoff, a refresh starts, but the caller no longer waits for it.
        provider.restore_discovery_response().await;
        let gate = provider.set_gated_jwks(vec![key_b()]).await;
        clock.advance(time::Duration::seconds(1));
        let refreshed =
            tokio::time::timeout(Duration::from_secs(1), discovery.refresh_expired_keys(3))
                .await
                .expect(
                    "the caller must not wait for the refresh, which would take up to five seconds",
                );
        assert_that!(refreshed).is_false();
        assert_that!(discovery.snapshot()).matches(partial!(RefreshStateSnapshot {
            pending: eq(true),
            generation: eq(3),
            ..
        }));

        gate.release();
        within_test_timeout(
            "the refresh of the expired keys must terminate after the gate opens",
            discovery.wait_for_completion(4),
        )
        .await;
        assert_that!(discovery.is_operational()).is_true();
        assert_that!(discovery.decoding_keys().exact("key-b")).is_some();
    }

    #[tokio::test]
    async fn stale_keys_get_a_refresh_without_waiting() {
        let provider = MockOidcServer::start().await;
        provider.set_jwks(vec![key_a()]).await;
        let clock = ManualClock::at_validation_time();
        let discovery =
            discovery_against(&provider, clock.clone(), discovery_config_without_jitter()).await;
        let gate = provider.set_gated_jwks(vec![key_b()]).await;

        clock.advance(time::Duration::minutes(4) - time::Duration::milliseconds(1));
        discovery.refresh_if_stale();
        assert_that!(discovery.snapshot().pending).is_false();

        clock.advance(time::Duration::milliseconds(1));
        discovery.refresh_if_stale();
        assert_that!(discovery.snapshot().pending).is_true();
        assert_that!(discovery.decoding_keys().exact("key-a")).is_some();

        gate.release();
        within_test_timeout(
            "the stale-key refresh must terminate after the gate opens",
            discovery.wait_for_completion(2),
        )
        .await;
        assert_that!(discovery.decoding_keys().exact("key-b")).is_some();
    }

    #[tokio::test]
    async fn requests_only_wait_for_a_refresh_that_started_recently() {
        let provider = MockOidcServer::start().await;
        provider.set_jwks(vec![key_a()]).await;
        let clock = ManualClock::at_validation_time();
        let discovery =
            discovery_against(&provider, clock.clone(), discovery_config_without_jitter()).await;
        let _gate = provider.set_gated_jwks(vec![key_b()]).await;

        // Start a refresh that hangs, without waiting for it.
        clock.advance(time::Duration::minutes(4));
        discovery.refresh_if_stale();
        assert_that!(discovery.snapshot().pending).is_true();

        // Shortly after it started, a request joins the refresh and waits for it.
        clock.advance(time::Duration::seconds(1));
        let joined = tokio::time::timeout(
            Duration::from_millis(100),
            discovery.refresh_if_needed(1, DiscoveryKind::UnknownKid),
        )
        .await;
        assert_that!(joined.is_err())
            .with_detail_message("a request must wait for a recently started refresh")
            .is_true();

        // Once the refresh took longer than requests may wait, they no longer wait for it.
        clock.advance(time::Duration::seconds(4));
        let joined = tokio::time::timeout(
            Duration::from_secs(1),
            discovery.refresh_if_needed(1, DiscoveryKind::UnknownKid),
        )
        .await
        .expect("a request must not wait for a refresh that already took too long");
        assert_that!(joined).is_false();
    }

    #[tokio::test]
    async fn a_hanging_discovery_times_out_as_a_failure() {
        let provider = MockOidcServer::start().await;
        provider.set_jwks(vec![key_a()]).await;
        let clock = ManualClock::at_validation_time();
        let discovery =
            discovery_against(&provider, clock.clone(), discovery_config_without_jitter()).await;
        let _gate = provider.set_gated_jwks(vec![key_b()]).await;
        clock.advance(time::Duration::minutes(4));
        discovery.refresh_if_stale();
        provider.wait_for_jwks_requests(2).await;

        clock.advance(time::Duration::seconds(60) - time::Duration::milliseconds(1));
        let_tasks_run().await;
        assert_that!(discovery.snapshot().pending).is_true();

        clock.advance(time::Duration::milliseconds(1));
        within_test_timeout(
            "the discovery must be abandoned at its timeout",
            discovery.wait_for_completion(2),
        )
        .await;
        assert_that!(discovery.snapshot()).matches(partial!(RefreshStateSnapshot {
            pending: IsFalse,
            consecutive_failures: eq(1),
            next_refresh_at: IsSome,
            ..
        }));
        assert_that!(
            discovery
                .operational_status()
                .last_error
                .map(|error| error.message)
        )
        .is_equal_to(Some(String::from(
            "The discovery did not finish within 60s",
        )));
        assert_that!(discovery.last_discovery_error()).is_matching(pattern!(Some(
            AuthError::DiscoveryTimedOut { timeout }
        ) if *timeout == Duration::from_secs(60)));
        assert_that!(discovery.decoding_keys().exact("key-a")).is_some();

        // The abandoned discovery no longer blocks later ones.
        provider.set_jwks(vec![key_b()]).await;
        clock.advance(time::Duration::seconds(1));
        assert_that!(
            discovery
                .refresh_if_needed(2, DiscoveryKind::UnknownKid)
                .await
        )
        .is_true();
        assert_that!(discovery.decoding_keys().exact("key-b")).is_some();
    }

    #[tokio::test]
    async fn key_age_counts_wall_clock_time_that_monotonic_time_missed() {
        let provider = MockOidcServer::start().await;
        provider.set_jwks(vec![key_a()]).await;
        let clock = ManualClock::at_validation_time();
        let discovery = discovery_against(
            &provider,
            clock.clone(),
            request_driven_config(ExpiredKeys::Reject),
        )
        .await;

        // Monotonic time stood still, as during a suspension, while wall-clock time moved on.
        clock.set(validation_time() + time::Duration::minutes(4));
        discovery.refresh_if_stale();
        assert_that!(discovery.snapshot().pending).is_true();
        within_test_timeout(
            "the stale-key refresh must terminate",
            discovery.wait_for_completion(2),
        )
        .await;
        assert_that!(discovery.is_operational()).is_true();

        // The refresh confirmed the keys at the new wall-clock time.
        clock.set(validation_time() + time::Duration::minutes(9) - time::Duration::milliseconds(1));
        assert_that!(discovery.is_operational()).is_true();
        clock.set(validation_time() + time::Duration::minutes(9));
        assert_that!(discovery.is_operational()).is_false();
        assert_that!(discovery.decoding_keys().is_expired()).is_true();

        // A wall clock set back does not make keys younger than monotonic time says.
        clock.set(validation_time());
        clock.advance(time::Duration::minutes(5));
        assert_that!(discovery.is_operational()).is_false();
    }

    #[tokio::test]
    async fn background_task_notices_keys_aging_on_the_wall_clock_only() {
        let provider = MockOidcServer::start().await;
        provider.set_jwks(vec![key_a()]).await;
        let clock = ManualClock::at_validation_time();
        let discovery = discovery_against(
            &provider,
            clock.clone(),
            background_config(ExpiredKeys::default()),
        )
        .await;

        // The background task sleeps until the keys are due on the monotonic clock. Then the wall
        // clock jumps ahead, as after a suspension, which that sleep does not notice.
        let_tasks_run().await;
        let before = discovery.snapshot();
        clock.set(validation_time() + time::Duration::minutes(4));
        let_tasks_run().await;
        assert_no_discovery_started_since(&discovery, &before);

        // The background task checks again within 30 seconds and refreshes the aged keys.
        clock.advance(time::Duration::seconds(30));
        within_test_timeout(
            "the background task must refresh keys aged on the wall clock",
            discovery.wait_for_completion(2),
        )
        .await;
        assert_that!(provider.discovery_requests()).is_equal_to(2);
    }

    #[tokio::test]
    async fn operational_status_reports_key_age_attempts_and_errors() {
        let provider = MockOidcServer::start().await;
        provider.set_jwks(vec![key_a()]).await;
        let clock = ManualClock::at_validation_time();
        let discovery =
            discovery_against(&provider, clock.clone(), discovery_config_without_jitter()).await;

        clock.advance(time::Duration::seconds(90));
        let status = discovery.operational_status();
        assert_that!(status.time_since_last_success).is_equal_to(Some(Duration::from_secs(90)));
        assert_that!(status.time_since_last_attempt).is_equal_to(Some(Duration::from_secs(90)));
        assert_that!(status.last_error.is_none()).is_true();
        assert_that!(status.consecutive_failures).is_equal_to(0);

        provider.make_discovery_unavailable().await;
        discovery
            .refresh_if_needed(1, DiscoveryKind::UnknownKid)
            .await;
        clock.advance(time::Duration::seconds(2));
        let status = discovery.operational_status();
        assert_that!(status.time_since_last_success).is_equal_to(Some(Duration::from_secs(92)));
        assert_that!(status.time_since_last_attempt).is_equal_to(Some(Duration::from_secs(2)));
        assert_that!(status.last_error.map(|error| error.elapsed))
            .is_equal_to(Some(Duration::from_secs(2)));
        assert_that!(status.consecutive_failures).is_equal_to(1);
    }

    /// A clock whose next monotonic reading panics once the test arms it.
    struct PanicOnArmedReadClock {
        inner: Arc<ManualClock>,
        armed: Arc<AtomicBool>,
    }

    impl Clock for PanicOnArmedReadClock {
        fn now_utc(&self) -> time::OffsetDateTime {
            self.inner.now_utc()
        }

        fn now_monotonic(&self) -> std::time::Instant {
            assert!(
                !self.armed.swap(false, Ordering::SeqCst),
                "requested monotonic clock panic"
            );
            self.inner.now_monotonic()
        }

        fn sleep_until(
            &self,
            deadline: std::time::Instant,
        ) -> futures::future::BoxFuture<'static, ()> {
            self.inner.sleep_until(deadline)
        }
    }

    #[tokio::test]
    async fn a_panic_while_recording_an_outcome_still_ends_the_discovery() {
        let mut discovery = Discovery::resolved(fixture_endpoint(), static_discovered_data());
        let armed = Arc::new(AtomicBool::new(false));
        discovery.shared_mut().clock = Arc::new(PanicOnArmedReadClock {
            inner: ManualClock::at_validation_time(),
            armed: armed.clone(),
        });
        // The discovery arms the clock, so that recording its outcome panics.
        let data = Arc::new(static_discovered_data());
        discovery.shared_mut().op = Arc::new(move |_endpoint, _request| {
            let armed = armed.clone();
            let data = data.clone();
            Box::pin(async move {
                armed.store(true, Ordering::SeqCst);
                Ok(data)
            })
        });

        let refreshed = within_test_timeout(
            "a panic while recording must still terminate the discovery",
            discovery.refresh_if_needed(1, DiscoveryKind::UnknownKid),
        )
        .await;

        assert_that!(refreshed).is_true();
        assert_that!(discovery.snapshot()).matches(partial!(RefreshStateSnapshot {
            pending: IsFalse,
            generation: eq(2),
            ..
        }));
        // The single-flight marker is free again, so the next refresh runs and succeeds.
        assert_that!(
            discovery
                .refresh_if_needed(2, DiscoveryKind::UnknownKid)
                .await
        )
        .is_true();
        assert_that!(discovery.snapshot().generation).is_equal_to(3);
    }

    #[tokio::test]
    async fn capped_refresh_wait_returns_instead_of_hanging() {
        let provider = MockOidcServer::start().await;
        provider.set_jwks(vec![key_a()]).await;
        let discovery = discovery_against(
            &provider,
            Arc::new(SystemClock),
            DiscoveryConfig {
                jitter_basis_points: 0,
                max_refresh_wait: Duration::from_millis(50),
                ..discovery_config_without_jitter()
            },
        )
        .await;
        let gate = provider.set_gated_jwks(vec![key_b()]).await;

        // The capped wait reports no newer generation instead of hanging on the gated provider,
        // so a request degrades to the current key set; the refresh itself continues detached.
        let refreshed = within_test_timeout(
            "a capped refresh wait must return instead of hanging",
            discovery.refresh_if_needed(1, DiscoveryKind::UnknownKid),
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
            discovery_against(
                &provider,
                Arc::new(SystemClock),
                discovery_config_without_jitter(),
            )
            .await,
        );
        let gate = provider.set_gated_jwks(vec![key_b()]).await;
        let waiting_caller = {
            let discovery = discovery.clone();
            tokio::spawn(async move {
                discovery
                    .refresh_if_needed(1, DiscoveryKind::UnknownKid)
                    .await
            })
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
            discovery_config_without_jitter(),
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
                discovery_config_without_jitter(),
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
        assert_that!(runtime.block_on(discovery.refresh_if_needed(1, DiscoveryKind::UnknownKid)))
            .is_true();

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
        discovery.shared_mut().clock = Arc::new(BlockingMonotonicClock {
            inner: ManualClock::at_validation_time(),
            block_next: AtomicBool::new(true),
            blocked: Mutex::new(Some(clock_blocked_tx)),
            release: Mutex::new(release_clock_rx),
        });
        discovery.shared_mut().config = discovery_config_without_jitter();
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
                .send(
                    discovery_for_refresh
                        .refresh_if_needed(1, DiscoveryKind::UnknownKid)
                        .await,
                )
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
        discovery.shared_mut().op =
            Arc::new(|_endpoint, _request| Box::pin(async { panic!("requested discovery panic") }));

        let initial_keys = discovery.decoding_keys();
        assert_that!(initial_keys.generation()).is_equal_to(1);
        assert_that!(initial_keys.all().count()).is_equal_to(1);

        // The resolved test discovery starts at generation 1; observing that generation forces a
        // new dispatch.
        within_test_timeout(
            "a panicking discovery must still terminate its waiters",
            discovery.refresh_if_needed(1, DiscoveryKind::UnknownKid),
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
