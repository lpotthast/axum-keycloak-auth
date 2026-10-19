//! An in-memory [`KeySource`], for testing the validation pipeline's key selection and refresh
//! decisions without a provider or any I/O.

use std::sync::{
    Arc, Mutex, MutexGuard,
    atomic::{AtomicUsize, Ordering},
};

use jsonwebtoken::jwk::Jwk;

use crate::{
    discovery::{DecodingKeys, DiscoveredData},
    validation::KeySource,
};

use super::{TEST_REALM, discovered_data_at, test_server_url};

/// A key source holding a fixed key set, an optional key set that the next refresh publishes,
/// and a count of refresh requests.
pub(crate) struct StaticKeySource {
    /// The published key set and its generation.
    published: Mutex<(Arc<DiscoveredData>, usize)>,
    next_keys: Mutex<Option<Vec<Jwk>>>,
    refresh_requests: AtomicUsize,
}

impl StaticKeySource {
    /// A key source trusting exactly `keys`, at generation 1.
    pub(crate) fn new(keys: Vec<Jwk>) -> Arc<Self> {
        Arc::new(Self {
            published: Mutex::new((Arc::new(Self::data(keys)), 1)),
            next_keys: Mutex::new(None),
            refresh_requests: AtomicUsize::new(0),
        })
    }

    /// The key set the next refresh publishes (as a new generation), simulating a provider-side
    /// rotation. Without it, a refresh publishes nothing and reports no newer generation.
    pub(crate) fn rotate_on_next_refresh(&self, keys: Vec<Jwk>) {
        *lock(&self.next_keys) = Some(keys);
    }

    /// How often the validator asked for a refresh.
    pub(crate) fn refresh_requests(&self) -> usize {
        self.refresh_requests.load(Ordering::Relaxed)
    }

    fn data(keys: Vec<Jwk>) -> DiscoveredData {
        discovered_data_at(&test_server_url(), TEST_REALM, keys)
    }
}

impl KeySource for StaticKeySource {
    fn decoding_keys(&self) -> DecodingKeys {
        let (data, generation) = &*lock(&self.published);
        DecodingKeys::new(Some(data.clone()), *generation)
    }

    // The trait fixes the async signature; this in-memory implementation completes immediately.
    #[allow(clippy::unused_async_trait_impl)]
    async fn refresh_if_needed(&self, observed_generation: usize) -> bool {
        self.refresh_requests.fetch_add(1, Ordering::Relaxed);
        let mut published = lock(&self.published);
        if published.1 > observed_generation {
            return true;
        }
        match lock(&self.next_keys).take() {
            Some(keys) => {
                *published = (Arc::new(Self::data(keys)), published.1 + 1);
                true
            }
            None => false,
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .expect("the static key source lock must not be poisoned")
}
