//! Capturing `tracing` output, for tests asserting what is (and is not) logged.

use std::{
    io,
    sync::{Arc, Mutex},
};

use assertr::prelude::*;
use tracing::subscriber::DefaultGuard;
use tracing_subscriber::fmt::MakeWriter;

/// An in-memory log sink. Clones share the same buffer.
///
/// ```ignore
/// let logs = CapturedLogs::default();
/// {
///     let _capture = logs.capture();
///     // Code under test.
/// }
/// assert_that!(logs.contents()).contains("expected event");
/// ```
#[derive(Clone, Default)]
pub(crate) struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

impl CapturedLogs {
    /// Records every event of every level emitted on the current thread into this buffer, until
    /// the returned guard is dropped.
    ///
    /// Events are formatted without timestamps or colors. Async tests stay captured across
    /// `.await` points because `#[tokio::test]` runs on a single thread.
    #[must_use = "logs are captured only while the guard is alive"]
    pub(crate) fn capture(&self) -> DefaultGuard {
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .with_writer(self.clone())
            .finish();
        tracing::subscriber::set_default(subscriber)
    }

    /// Everything captured so far.
    pub(crate) fn contents(&self) -> String {
        String::from_utf8(self.buffer().clone()).expect("tracing output must be UTF-8")
    }

    fn buffer(&self) -> std::sync::MutexGuard<'_, Vec<u8>> {
        self.0
            .lock()
            .expect("the captured log lock must not be poisoned")
    }
}

impl io::Write for CapturedLogs {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'writer> MakeWriter<'writer> for CapturedLogs {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}

/// Asserts that the captured `logs` contain `expected` if and only if `logged` is set.
#[track_caller]
pub(crate) fn assert_logged_iff(
    logs: &str,
    expected: &str,
    logged: bool,
    subject_name: impl Into<String>,
) {
    let logs = assert_that!(logs).with_subject_name(subject_name);
    if logged {
        logs.contains(expected);
    } else {
        logs.does_not_contain(expected);
    }
}

#[cfg(test)]
mod tests {
    use assertr::prelude::*;

    use super::CapturedLogs;

    #[test]
    fn captures_events_only_while_the_guard_is_alive() {
        let logs = CapturedLogs::default();

        {
            let _capture = logs.capture();
            tracing::trace!("captured event");
        }
        tracing::error!("event after the capture ended");

        assert_that!(logs.contents())
            .contains("TRACE")
            .contains("captured event")
            .does_not_contain("event after the capture ended");
    }
}
