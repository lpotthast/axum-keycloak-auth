//! Logging at a severity chosen at runtime.

/// Emits a `tracing` event at the runtime `tracing::Level` given as the first argument. The
/// remaining arguments are the fields and message, as for `tracing::event!`.
///
/// `tracing` requires the level of an event to be a constant, so this dispatches to one constant
/// level callsite per level.
macro_rules! event_at_level {
    ($level:expr, $($event:tt)+) => {
        match $level {
            ::tracing::Level::ERROR => ::tracing::error!($($event)+),
            ::tracing::Level::WARN => ::tracing::warn!($($event)+),
            ::tracing::Level::INFO => ::tracing::info!($($event)+),
            ::tracing::Level::DEBUG => ::tracing::debug!($($event)+),
            ::tracing::Level::TRACE => ::tracing::trace!($($event)+),
        }
    };
}

pub(crate) use event_at_level;

#[cfg(test)]
mod tests {
    use assertr::prelude::*;

    use crate::test_support::CapturedLogs;

    #[test]
    fn event_at_level_uses_the_given_level() {
        for (case_name, level) in [
            ("error", tracing::Level::ERROR),
            ("warning", tracing::Level::WARN),
            ("information", tracing::Level::INFO),
            ("debug", tracing::Level::DEBUG),
            ("trace", tracing::Level::TRACE),
        ] {
            let logs = CapturedLogs::default();
            {
                let _capture = logs.capture();
                event_at_level!(level, dispatch_case = case_name, "runtime-level dispatch");
            }

            let event = logs.event_containing(case_name);
            assert_that!(event.level())
                .with_subject_name(format!("{case_name}: event level"))
                .is_equal_to(level);
            assert_that!(event.field("message"))
                .with_subject_name(format!("{case_name}: event message"))
                .is_equal_to(Some("runtime-level dispatch"));
        }
    }
}
