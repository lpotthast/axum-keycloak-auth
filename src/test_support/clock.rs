use std::{
    sync::{Arc, Mutex},
    time::{Duration as StdDuration, Instant},
};

use assertr::prelude::*;
use time::{Duration, OffsetDateTime};

use crate::clock::Clock;

#[derive(Debug, Clone)]
pub(crate) struct ManualClock {
    state: Arc<Mutex<ManualClockState>>,
}

#[derive(Debug)]
struct ManualClockState {
    utc: OffsetDateTime,
    monotonic: Instant,
}

impl ManualClock {
    pub(crate) fn new(now: OffsetDateTime) -> Self {
        Self {
            state: Arc::new(Mutex::new(ManualClockState {
                utc: now,
                monotonic: Instant::now(),
            })),
        }
    }

    pub(crate) fn set(&self, now: OffsetDateTime) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|err| panic!("manual clock mutex was poisoned: {err}"));
        state.utc = now;
    }

    pub(crate) fn advance(&self, duration: Duration) {
        assert_that!(duration)
            .with_subject_name("manual clock advance duration")
            .is_greater_or_equal_to(Duration::ZERO);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|err| panic!("manual clock mutex was poisoned: {err}"));
        state.utc += duration;
        state.monotonic = shift_instant(state.monotonic, duration);
    }
}

impl Clock for ManualClock {
    fn now_utc(&self) -> OffsetDateTime {
        self.state
            .lock()
            .unwrap_or_else(|err| panic!("manual clock mutex was poisoned: {err}"))
            .utc
    }

    fn now_monotonic(&self) -> Instant {
        self.state
            .lock()
            .unwrap_or_else(|err| panic!("manual clock mutex was poisoned: {err}"))
            .monotonic
    }
}

fn shift_instant(instant: Instant, duration: Duration) -> Instant {
    let magnitude = StdDuration::try_from(duration)
        .unwrap_or_else(|err| panic!("manual clock duration must fit std::time::Duration: {err}"));
    instant
        .checked_add(magnitude)
        .unwrap_or_else(|| panic!("manual clock advance overflowed Instant"))
}
