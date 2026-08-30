//! Wall-clock and monotonic time used by validation and discovery.

use std::time::Instant;

use time::OffsetDateTime;

pub(crate) trait Clock: Send + Sync {
    fn now_utc(&self) -> OffsetDateTime;
    fn now_monotonic(&self) -> Instant;
}

#[derive(Debug)]
pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn now_utc(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    fn now_monotonic(&self) -> Instant {
        Instant::now()
    }
}
