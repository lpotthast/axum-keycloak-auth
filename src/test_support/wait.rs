//! Bounded waiting, so a concurrency regression fails a test quickly instead of hanging the
//! suite.

use std::{future::IntoFuture, time::Duration};

/// Upper bound for any single wait in a test. Generous for local work, which completes in
/// milliseconds, and short enough that a hang is reported promptly.
pub(crate) const TEST_TIMEOUT: Duration = Duration::from_secs(2);

/// Awaits `future`, panicking with `expectation` if it does not complete within [`TEST_TIMEOUT`].
///
/// Phrase `expectation` as the requirement that was violated, for example "the refresh must
/// terminate".
pub(crate) async fn within_test_timeout<F: IntoFuture>(expectation: &str, future: F) -> F::Output {
    tokio::time::timeout(TEST_TIMEOUT, future)
        .await
        .unwrap_or_else(|_elapsed| panic!("timed out after {TEST_TIMEOUT:?}: {expectation}"))
}

/// Yields to other tasks until `condition` holds, panicking with `expectation` if it does not
/// hold within [`TEST_TIMEOUT`].
pub(crate) async fn wait_until(expectation: &str, mut condition: impl FnMut() -> bool) {
    within_test_timeout(expectation, async {
        while !condition() {
            tokio::task::yield_now().await;
        }
    })
    .await;
}
