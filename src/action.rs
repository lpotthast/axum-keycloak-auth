use std::{
    fmt::Debug,
    option::Option,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize},
        Arc,
    },
};

use atomic_time::AtomicOptionInstant;
use educe::Educe;
use futures::Future;
use tokio::{
    sync::Notify,
    sync::{futures::Notified, RwLock},
    task::JoinHandle,
};

#[derive(Educe)]
#[educe(Debug)]
pub(crate) struct Action<I: Debug + Clone + Send + Sync + 'static, O: Debug + Send + Sync + 'static>
{
    /// The current argument that was dispatched to the `async` function.
    /// `Some` while we are waiting for it to resolve, `None` if it has resolved.
    input: Arc<RwLock<Option<I>>>,

    /// Last staring time at which the operation was dispatched.
    #[educe(Debug(ignore))]
    input_send: Arc<AtomicOptionInstant>,

    #[educe(Debug(ignore))]
    #[allow(clippy::complexity)]
    action_fn: Arc<dyn Fn(&I) -> Pin<Box<dyn Future<Output = O> + Send + Sync>> + Send + Sync>,

    /// Might be Some if there still is an ongoing operation.
    pending: Arc<AtomicBool>,

    notify: Arc<Notify>,

    /// The most recent return value of the `async` function.
    value: Arc<RwLock<Option<O>>>,

    /// Time the last value was received. None if we never received a value.
    #[educe(Debug(ignore))]
    value_received: Arc<AtomicOptionInstant>,

    /// How many times the action has successfully resolved.
    /// Version 0 indicates that no value was received yet.
    version: Arc<AtomicUsize>,
}

#[allow(dead_code)]
impl<I: Debug + Clone + Send + Sync + 'static, O: Debug + Send + Sync + 'static> Action<I, O> {
    pub(crate) fn new<F, Fu>(action_fn: F) -> Self
    where
        F: Fn(&I) -> Fu + Send + Sync + 'static,
        Fu: Future<Output = O> + Send + Sync + 'static,
    {
        let action_fn = Arc::new(move |input: &I| {
            let fut = action_fn(input);
            Box::pin(fut) as Pin<Box<dyn Future<Output = O> + Send + Sync>>
        });

        Self {
            input: Arc::new(RwLock::new(None)),
            input_send: Arc::new(AtomicOptionInstant::none()),
            action_fn,
            pending: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
            value: Arc::new(RwLock::new(None)),
            value_received: Arc::new(AtomicOptionInstant::none()),
            version: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Await the next completion of this action.
    /// Useful if the action is already pending and you are interested in its upcoming value.
    pub(crate) fn notified(&self) -> Notified<'_> {
        self.notify.notified()
    }

    pub(crate) fn is_pending(&self) -> bool {
        self.pending.load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) fn pending_for(&self) -> std::time::Duration {
        let started_at: std::time::Instant = self.input_send().expect("Start time when pending");
        std::time::Instant::now() - started_at
    }

    pub(crate) async fn input(&self) -> tokio::sync::RwLockReadGuard<'_, Option<I>> {
        self.input.read().await
    }

    pub(crate) fn input_send(&self) -> Option<std::time::Instant> {
        self.input_send.load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) async fn value(&self) -> tokio::sync::RwLockReadGuard<'_, Option<O>> {
        self.value.read().await
    }

    pub(crate) fn value_received(&self) -> Option<std::time::Instant> {
        self.value_received
            .load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) fn version(&self) -> usize {
        self.version.load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) fn dispatch(&self, action_input: I) -> JoinHandle<()> {
        let fut = (self.action_fn)(&action_input);
        let input = self.input.clone();
        let input_send = self.input_send.clone();
        let version = self.version.clone();
        let pending = self.pending.clone();
        let notify = self.notify.clone();
        let value = self.value.clone();
        let value_received = self.value_received.clone();

        tokio::spawn(async move {
            let started = Some(std::time::Instant::now());

            *input.write().await = Some(action_input.clone());
            input_send.store(started, std::sync::atomic::Ordering::Release);
            pending.store(true, std::sync::atomic::Ordering::Release);
            let new_value: O = fut.await;
            let new_value_received_at = Some(std::time::Instant::now());
            *value.write().await = Some(new_value);
            value_received.store(new_value_received_at, std::sync::atomic::Ordering::Release);
            version.fetch_add(1, std::sync::atomic::Ordering::Release);
            *input.write().await = None;
            pending.store(false, std::sync::atomic::Ordering::Release);
            notify.notify_waiters();
        })
    }
}
