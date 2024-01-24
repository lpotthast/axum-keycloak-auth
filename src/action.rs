use std::{
    pin::Pin,
    sync::{atomic::AtomicBool, Arc},
};

use futures::Future;
use tokio::{sync::RwLock, task::JoinHandle};

pub(crate) struct Action<I: Clone + Send + Sync + 'static, O: Send + Sync + 'static> {
    /// The current argument that was dispatched to the `async` function.
    /// `Some` while we are waiting for it to resolve, `None` if it has resolved.
    pub(crate) input: Arc<RwLock<Option<I>>>,

    /// How many dispatched actions are still pending.
    //pending_dispatches: Rc<Cell<usize>>,

    #[allow(clippy::complexity)]
    action_fn: Arc<dyn Fn(&I) -> Pin<Box<dyn Future<Output = O> + Send + Sync>> + Send + Sync>,

    /// Might be Some if there still is an ongoing operation.
    //pub(crate) jh: Arc<RwLock<Option<JoinHandle<O>>>>,
    pub(crate) pending: Arc<AtomicBool>, // pending?

    /// The most recent return value of the `async` function.
    pub(crate) value: Arc<RwLock<Option<O>>>,

    /// Time the last value was received. None if we never received a value.
    pub(crate) value_received: Arc<RwLock<Option<time::OffsetDateTime>>>,

    /// How many times the action has successfully resolved.
    pub(crate) version: Arc<RwLock<usize>>,
}

impl<I: Clone + Send + Sync + 'static, O: Send + Sync + 'static> Action<I, O> {
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
            value: Arc::new(RwLock::new(None)),
            value_received: Arc::new(RwLock::new(None)),
            version: Arc::new(RwLock::new(0)),
        }
    }

    pub(crate) fn is_pending(&self) -> bool {
        self.pending.load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) fn dispatch(&self, action_input: I) -> JoinHandle<()> {
        let fut = (self.action_fn)(&action_input);
        let input = self.input.clone();
        let version = self.version.clone();
        let pending = self.pending.clone();
        let value = self.value.clone();
        let value_received = self.value_received.clone();

        tokio::spawn(async move {
            *input.write().await = Some(action_input.clone());
            pending.store(true, std::sync::atomic::Ordering::Release);
            let new_value = fut.await;
            let new_value_recv_at = time::OffsetDateTime::now_utc();
            *value.write().await = Some(new_value);
            *value_received.write().await = Some(new_value_recv_at);
            *version.write().await += 1;
            *input.write().await = None;
            pending.store(false, std::sync::atomic::Ordering::Release);
        })
    }
}