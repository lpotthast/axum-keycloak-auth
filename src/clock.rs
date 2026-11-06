//! Wall-clock and monotonic time used by validation and discovery.

use std::time::Instant;

use futures::future::BoxFuture;
use time::OffsetDateTime;

pub(crate) trait Clock: Send + Sync {
    fn now_utc(&self) -> OffsetDateTime;
    fn now_monotonic(&self) -> Instant;
    /// Completes once [`Self::now_monotonic`] has reached `deadline`.
    fn sleep_until(&self, deadline: Instant) -> BoxFuture<'static, ()>;
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

    fn sleep_until(&self, deadline: Instant) -> BoxFuture<'static, ()> {
        Box::pin(tokio::time::sleep_until(deadline.into()))
    }
}
