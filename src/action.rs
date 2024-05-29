use std::{
    fmt::Debug,
    pin::Pin,
    sync::{atomic::AtomicBool, Arc},
};

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

    #[educe(Debug(ignore))]
    #[allow(clippy::complexity)]
    action_fn: Arc<dyn Fn(&I) -> Pin<Box<dyn Future<Output = O> + Send + Sync>> + Send + Sync>,

    /// Might be Some if there still is an ongoing operation.
    pending: Arc<AtomicBool>,

    notify: Arc<Notify>,

    /// The most recent return value of the `async` function.
    value: Arc<RwLock<Option<O>>>,

    /// Time the last value was received. None if we never received a value.
    value_received: Arc<RwLock<Option<time::OffsetDateTime>>>,

    /// How many times the action has successfully resolved.
    version: Arc<RwLock<usize>>,
}

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
            action_fn,
            pending: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
            value: Arc::new(RwLock::new(None)),
            value_received: Arc::new(RwLock::new(None)),
            version: Arc::new(RwLock::new(0)),
        }
    }

    pub(crate) fn notified(&self) -> Notified<'_> {
        self.notify.notified()
    }

    pub(crate) fn is_pending(&self) -> bool {
        self.pending.load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) async fn value(&self) -> tokio::sync::RwLockReadGuard<'_, std::option::Option<O>> {
        self.value.read().await
    }

    #[allow(dead_code)]
    pub(crate) async fn value_received(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, std::option::Option<time::OffsetDateTime>> {
        self.value_received.read().await
    }

    #[allow(dead_code)]
    pub(crate) async fn version(&self) -> usize {
        *self.version.read().await
    }

    pub(crate) fn dispatch(&self, action_input: I) -> JoinHandle<()> {
        let fut = (self.action_fn)(&action_input);
        let input = self.input.clone();
        let version = self.version.clone();
        let pending = self.pending.clone();
        let notify = self.notify.clone();
        let value = self.value.clone();
        let value_received = self.value_received.clone();

        tokio::spawn(async move {
            *input.write().await = Some(action_input.clone());
            pending.store(true, std::sync::atomic::Ordering::Release);
            let new_value = fut.await;
            let new_value_received_at = time::OffsetDateTime::now_utc();
            *value.write().await = Some(new_value);
            *value_received.write().await = Some(new_value_received_at);
            *version.write().await += 1;
            *input.write().await = None;
            pending.store(false, std::sync::atomic::Ordering::Release);
            notify.notify_waiters();
        })
    }
}
