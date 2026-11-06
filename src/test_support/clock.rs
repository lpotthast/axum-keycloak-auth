//! A [`Clock`] that only moves when a test moves it.

use std::{
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration as StdDuration, Instant},
};

use assertr::prelude::*;
use futures::future::BoxFuture;
use time::{Duration, OffsetDateTime};
use tokio::sync::watch;

use crate::clock::Clock;

use super::validation_time;

/// A manually driven clock. Clones share the same time.
///
/// Wall-clock time (used for token lifetimes) and monotonic time (used for refresh cooldowns and
/// backoff) are tracked separately: [`Self::advance`] moves both, while [`Self::set`] jumps the
/// wall clock only, like an NTP correction.
#[derive(Debug, Clone)]
pub(crate) struct ManualClock {
    state: Arc<Mutex<ManualClockState>>,
    /// Publishes every monotonic time the clock moves to, waking sleepers.
    monotonic_ticks: Arc<watch::Sender<Instant>>,
}

#[derive(Debug)]
struct ManualClockState {
    utc: OffsetDateTime,
    monotonic: Instant,
}

impl ManualClock {
    /// A clock showing `now`, with its monotonic time starting at the real current instant.
    pub(crate) fn new(now: OffsetDateTime) -> Self {
        let monotonic = Instant::now();
        Self {
            state: Arc::new(Mutex::new(ManualClockState {
                utc: now,
                monotonic,
            })),
            monotonic_ticks: Arc::new(watch::Sender::new(monotonic)),
        }
    }

    /// A shared clock showing [`validation_time`], ready to be passed as `Arc<dyn Clock>`.
    pub(crate) fn at_validation_time() -> Arc<Self> {
        Arc::new(Self::new(validation_time()))
    }

    /// Jumps the wall clock to `now` without moving monotonic time.
    pub(crate) fn set(&self, now: OffsetDateTime) {
        self.state().utc = now;
    }

    /// Moves wall-clock and monotonic time forward by `duration`.
    ///
    /// # Panics
    ///
    /// Panics if `duration` is negative.
    pub(crate) fn advance(&self, duration: Duration) {
        assert_that!(duration)
            .with_subject_name("manual clock advance duration")
            .is_greater_or_equal_to(Duration::ZERO);
        let forward = StdDuration::try_from(duration)
            .expect("a non-negative duration must fit std::time::Duration");
        let mut state = self.state();
        state.utc += duration;
        state.monotonic = state
            .monotonic
            .checked_add(forward)
            .expect("manual clock advance must not overflow Instant");
        self.monotonic_ticks.send_replace(state.monotonic);
    }

    fn state(&self) -> MutexGuard<'_, ManualClockState> {
        self.state
            .lock()
            .expect("the manual clock mutex must not be poisoned")
    }
}

impl Clock for ManualClock {
    fn now_utc(&self) -> OffsetDateTime {
        self.state().utc
    }

    fn now_monotonic(&self) -> Instant {
        self.state().monotonic
    }

    fn sleep_until(&self, deadline: Instant) -> BoxFuture<'static, ()> {
        let mut ticks = self.monotonic_ticks.subscribe();
        Box::pin(async move {
            while *ticks.borrow_and_update() < deadline {
                if ticks.changed().await.is_err() {
                    return std::future::pending().await;
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use assertr::prelude::*;

    use crate::{clock::Clock, test_support::validation_time};

    use super::ManualClock;

    #[tokio::test]
    async fn sleepers_wake_once_monotonic_time_reaches_their_deadline() {
        let clock = ManualClock::new(validation_time());
        let start = clock.now_monotonic();

        // A deadline already reached completes immediately.
        clock.sleep_until(start).await;

        let mut sleep = clock.sleep_until(start + Duration::from_secs(10));
        assert_that!(futures::poll!(&mut sleep).is_pending()).is_true();

        // Moving only the wall clock does not wake sleepers.
        clock.set(validation_time() + time::Duration::hours(1));
        assert_that!(futures::poll!(&mut sleep).is_pending()).is_true();

        clock.advance(time::Duration::milliseconds(9_999));
        assert_that!(futures::poll!(&mut sleep).is_pending()).is_true();

        clock.advance(time::Duration::milliseconds(1));
        assert_that!(futures::poll!(&mut sleep).is_ready()).is_true();
    }

    #[test]
    fn manual_clock_can_be_set_and_advanced() {
        let clock = ManualClock::new(validation_time());
        let initial_monotonic = clock.now_monotonic();
        assert_that!(clock.now_utc()).is_equal_to(validation_time());

        clock.advance(time::Duration::seconds(30));
        assert_that!(clock.now_utc()).is_equal_to(validation_time() + time::Duration::seconds(30));
        assert_that!(clock.now_monotonic().duration_since(initial_monotonic))
            .is_equal_to(Duration::from_secs(30));

        clock.set(validation_time() - time::Duration::seconds(10));
        assert_that!(clock.now_utc()).is_equal_to(validation_time() - time::Duration::seconds(10));
        assert_that!(clock.now_monotonic().duration_since(initial_monotonic))
            .is_equal_to(Duration::from_secs(30));
    }

    #[test]
    fn clones_share_the_same_time() {
        let clock = ManualClock::new(validation_time());
        let clone = clock.clone();

        clock.advance(time::Duration::seconds(5));

        assert_that!(clone.now_utc()).is_equal_to(clock.now_utc());
        assert_that!(clone.now_monotonic()).is_equal_to(clock.now_monotonic());
    }
}
