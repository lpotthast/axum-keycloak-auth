use std::{
    io,
    sync::{Arc, Mutex},
};

use assertr::prelude::*;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
pub(crate) struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

pub(crate) struct CapturedLogWriter(Arc<Mutex<Vec<u8>>>);

impl CapturedLogs {
    pub(crate) fn contents(&self) -> String {
        String::from_utf8(
            self.0
                .lock()
                .expect("captured log lock must not be poisoned")
                .clone(),
        )
        .expect("tracing output must be UTF-8")
    }
}

impl io::Write for CapturedLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("captured log lock must not be poisoned")
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'writer> MakeWriter<'writer> for CapturedLogs {
    type Writer = CapturedLogWriter;

    fn make_writer(&'writer self) -> Self::Writer {
        CapturedLogWriter(self.0.clone())
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
