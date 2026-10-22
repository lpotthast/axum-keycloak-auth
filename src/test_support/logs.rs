//! Capturing `tracing` output, for tests asserting what is (and is not) logged.
//!
//! Tests must never install their own subscriber with [`tracing::subscriber::set_default`].
//! `tracing` caches every callsite's `Interest` process-wide, and while a scoped subscriber is the
//! only registered dispatcher, `tracing_core` fills that cache from whichever thread hits the
//! callsite first: its `Dispatchers::rebuilder` takes a `JustOne` shortcut that asks
//! `dispatcher::get_default` on the hitting thread. A test running in parallel without a subscriber
//! therefore caches `Interest::never()` for a callsite another test is about to assert on, and that
//! event is dropped before it can reach the capturing thread.
//!
//! This module removes the hazard by registering exactly one dispatcher for the whole test binary:
//! a global default subscriber, installed once, that routes each event to the capture active on the
//! emitting thread and discards the rest. A global default is reachable from every thread, so
//! whoever fills the interest cache computes the same, correct answer.
//!
//! Capture is per thread. [`CapturedLogs::capture`] records the events emitted on the thread that
//! called it, including those from tasks a current-thread runtime drives on that thread, and never
//! observes a test running in parallel. Events emitted on threads a test spawns itself
//! (multi-threaded runtime workers, `spawn_blocking`, `std::thread::spawn`) belong to those threads
//! and are not captured.

use std::{
    cell::RefCell,
    collections::BTreeMap,
    fmt, io,
    marker::PhantomData,
    sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError},
};

use assertr::prelude::*;
use tracing::{Event, Subscriber, field::Visit};
use tracing_subscriber::{Layer, fmt::MakeWriter, layer::SubscriberExt};

/// An in-memory log sink. Clones share the same buffer.
///
/// ```ignore
/// let logs = CapturedLogs::default();
/// {
///     let _capture = logs.capture();
///     // Code under test.
/// }
/// assert_that!(logs.contents()).contains("expected event");
/// assert_that!(logs.event_containing("expected event").level()).is_equal_to(Level::WARN);
/// ```
#[derive(Clone, Default)]
pub(crate) struct CapturedLogs(Arc<Sink>);

#[derive(Debug, Default)]
struct Sink {
    rendered: Mutex<Vec<u8>>,
    events: Mutex<Vec<CapturedEvent>>,
}

/// Structured metadata and fields of one captured event.
#[derive(Debug, Clone)]
pub(crate) struct CapturedEvent {
    level: tracing::Level,
    target: &'static str,
    fields: BTreeMap<&'static str, String>,
}

impl CapturedEvent {
    pub(crate) fn level(&self) -> tracing::Level {
        self.level
    }

    /// The recorded value of field `name`. The event's message is the field `"message"`.
    pub(crate) fn field(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }

    fn contains(&self, needle: &str) -> bool {
        self.target.contains(needle)
            || self
                .fields
                .iter()
                .any(|(name, value)| name.contains(needle) || value.contains(needle))
    }
}

thread_local! {
    /// The sinks capturing on this thread, innermost last.
    static ACTIVE: RefCell<Vec<Arc<Sink>>> = const { RefCell::new(Vec::new()) };
}

/// Keeps a [`CapturedLogs`] capturing the current thread's events until it is dropped.
#[must_use = "logs are captured only while the guard is alive"]
pub(crate) struct CaptureGuard {
    sink: Arc<Sink>,
    /// Dropping the guard updates a thread-local, so it must not move to another thread.
    _not_send: PhantomData<*const ()>,
}

impl CapturedLogs {
    /// Records every event of every level emitted on the current thread into this buffer, until
    /// the returned guard is dropped. Captures may nest, in which case the innermost one receives
    /// the events.
    ///
    /// Events are rendered without timestamps or colors. Async tests stay captured across
    /// `.await` points because `#[tokio::test]` runs on a single thread.
    pub(crate) fn capture(&self) -> CaptureGuard {
        install_capturing_subscriber();
        ACTIVE.with_borrow_mut(|active| active.push(self.0.clone()));
        CaptureGuard {
            sink: self.0.clone(),
            _not_send: PhantomData,
        }
    }

    /// Everything captured so far, rendered the way `tracing_subscriber::fmt` renders it.
    pub(crate) fn contents(&self) -> String {
        String::from_utf8(lock(&self.0.rendered).clone()).expect("tracing output must be UTF-8")
    }

    /// The first captured event whose target, field name, or field value contains `needle`.
    /// Panics with both structured and rendered output when none matches.
    #[track_caller]
    pub(crate) fn event_containing(&self, needle: &str) -> CapturedEvent {
        let events = lock(&self.0.events);
        let Some(event) = events.iter().find(|event| event.contains(needle)).cloned() else {
            let structured = events.clone();
            drop(events);
            let rendered = self.contents();
            panic!(
                "no captured event contains {needle:?}. Structured events: {structured:#?}\n\
                 Rendered events:\n{rendered}"
            )
        };
        event
    }
}

impl Drop for CaptureGuard {
    fn drop(&mut self) {
        ACTIVE.with_borrow_mut(|active| {
            if let Some(index) = active
                .iter()
                .rposition(|sink| Arc::ptr_eq(sink, &self.sink))
            {
                active.remove(index);
            }
        });
    }
}

/// Installs the one subscriber every event in this test binary is dispatched to. Idempotent, so any
/// test may be the first one to capture.
fn install_capturing_subscriber() {
    static INSTALLED: OnceLock<()> = OnceLock::new();

    INSTALLED.get_or_init(|| {
        let subscriber = tracing_subscriber::registry().with(StructuredCapture).with(
            tracing_subscriber::fmt::layer()
                .without_time()
                .with_ansi(false)
                .with_writer(ThreadLocalCapture),
        );
        tracing::subscriber::set_global_default(subscriber)
            .expect("the capture subscriber must be the only global subscriber of a test binary");

        // `set_global_default` publishes the dispatcher only after having raised the global max
        // level and rebuilt the interest cache. Callsites first hit by a parallel test in that
        // window still resolve to no subscriber and would cache `Interest::never()` forever, so
        // re-evaluate the cache now that the global default is reachable.
        tracing_core::callsite::rebuild_interest_cache();
    });
}

fn innermost_sink() -> Option<Arc<Sink>> {
    ACTIVE.with_borrow(|active| active.last().cloned())
}

/// Records each event's structured fields into the innermost sink of the emitting thread.
struct StructuredCapture;

impl<S> Layer<S> for StructuredCapture
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _context: tracing_subscriber::layer::Context<'_, S>) {
        let Some(sink) = innermost_sink() else {
            return;
        };
        let metadata = event.metadata();
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);
        lock(&sink.events).push(CapturedEvent {
            level: *metadata.level(),
            target: metadata.target(),
            fields: visitor.fields,
        });
    }
}

#[derive(Default)]
struct FieldVisitor {
    fields: BTreeMap<&'static str, String>,
}

impl Visit for FieldVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        self.fields.insert(field.name(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.fields.insert(field.name(), String::from(value));
    }
}

/// Hands each rendered event to the innermost sink of the emitting thread.
struct ThreadLocalCapture;

struct CaptureWriter(Option<Arc<Sink>>);

impl<'writer> MakeWriter<'writer> for ThreadLocalCapture {
    type Writer = CaptureWriter;

    fn make_writer(&'writer self) -> Self::Writer {
        CaptureWriter(innermost_sink())
    }
}

impl io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(sink) = &self.0 {
            lock(&sink.rendered).extend_from_slice(buf);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A capturing test that panics leaves its sink poisoned. The captured output stays intact and is
/// exactly what the failure report needs, so recover it instead of panicking again.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
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

    fn emit_probe(message: &str) {
        tracing::debug!(probe = message, "capture probe");
    }

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

    #[test]
    fn records_the_events_of_its_own_thread_and_no_others() {
        let logs = CapturedLogs::default();
        {
            let _capture = logs.capture();
            emit_probe("own-thread");
            std::thread::spawn(|| emit_probe("sibling-thread"))
                .join()
                .expect("the sibling thread must not panic");
        }

        let event = logs.event_containing("own-thread");
        assert_that!(event.level()).is_equal_to(tracing::Level::DEBUG);
        assert_that!(event.field("message")).is_equal_to(Some("capture probe"));
        assert_that!(event.field("probe")).is_equal_to(Some("own-thread"));
        assert_that!(logs.contents())
            .with_subject_name("events of a thread that captures nothing")
            .does_not_contain("sibling-thread");
    }

    /// A callsite's `Interest` is cached process-wide by whichever thread hits it first. Capturing
    /// must not depend on that thread having had a capture installed, which is what made
    /// log-asserting tests flaky while every test installed its own scoped subscriber.
    #[test]
    fn captures_a_callsite_first_hit_by_a_thread_without_capture() {
        // Interest is cached per callsite, so this test needs one no other test can warm up first.
        fn emit_cold_probe() {
            tracing::debug!("cold callsite probe");
        }

        // Installing and dropping a capture puts the global subscriber in place without leaving one
        // active, so the priming thread below hits the callsite exactly as an unrelated test would.
        drop(CapturedLogs::default().capture());
        std::thread::spawn(emit_cold_probe)
            .join()
            .expect("the priming thread must not panic");

        let logs = CapturedLogs::default();
        {
            let _capture = logs.capture();
            emit_cold_probe();
        }

        assert_that!(
            logs.event_containing("cold callsite probe")
                .field("message")
        )
        .is_equal_to(Some("cold callsite probe"));
        assert_that!(logs.contents()).contains("cold callsite probe");
    }

    #[test]
    fn nested_captures_record_into_the_innermost_one() {
        let outer = CapturedLogs::default();
        let inner = CapturedLogs::default();
        {
            let _outer_capture = outer.capture();
            emit_probe("before-nesting");
            {
                let _inner_capture = inner.capture();
                emit_probe("while-nested");
            }
            emit_probe("after-nesting");
        }

        assert_that!(inner.contents())
            .contains("while-nested")
            .does_not_contain("before-nesting")
            .does_not_contain("after-nesting");
        assert_that!(outer.contents())
            .contains("before-nesting")
            .contains("after-nesting")
            .does_not_contain("while-nested");
    }
}
