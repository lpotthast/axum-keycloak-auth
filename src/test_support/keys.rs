//! An in-memory [`KeySource`] double: a fixed key set, an optional next key set that a refresh
//! publishes, and a count of refresh requests. Lets pipeline tests assert refresh decisions
//! directly, without a mock provider or any I/O.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use jsonwebtoken::jwk::{Jwk, JwkSet};
use url::Url;

use crate::{
    discovery::{DecodingKeys, DiscoveredData},
    validation::KeySource,
};

use super::instance::static_discovered_data_with_keys;

pub(crate) struct StaticKeySource {
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
        *self.next_keys.lock().expect("next keys lock") = Some(keys);
    }

    /// How often the validator asked for a refresh.
    pub(crate) fn refresh_requests(&self) -> usize {
        self.refresh_requests.load(Ordering::Relaxed)
    }

    fn data(keys: Vec<Jwk>) -> DiscoveredData {
        let server = Url::parse("https://issuer.example/").expect("static issuer URL must parse");
        static_discovered_data_with_keys(&server, "test-realm", &JwkSet { keys })
    }
}

impl KeySource for StaticKeySource {
    fn decoding_keys(&self) -> DecodingKeys {
        let (data, generation) = &*self.published.lock().expect("published lock");
        DecodingKeys::new(Some(data.clone()), *generation)
    }

    // The trait fixes the async signature; this in-memory implementation completes immediately.
    #[allow(clippy::unused_async_trait_impl)]
    async fn refresh_if_needed(&self, observed_generation: usize) -> bool {
        self.refresh_requests.fetch_add(1, Ordering::Relaxed);
        let mut published = self.published.lock().expect("published lock");
        if published.1 > observed_generation {
            return true;
        }
        match self.next_keys.lock().expect("next keys lock").take() {
            Some(keys) => {
                *published = (Arc::new(Self::data(keys)), published.1 + 1);
                true
            }
            None => false,
        }
    }
}
