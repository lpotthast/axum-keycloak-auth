//! An in-process mock OIDC provider: a discovery document and a JWKS endpoint whose responses a
//! test controls (key sets, failures, gated responses), with per-endpoint request counters.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::Response,
    routing::get,
};
use jsonwebtoken::jwk::{Jwk, JwkSet};
use serde_json::{Value, json};
use tokio::{
    net::TcpListener,
    sync::{Mutex, Semaphore, oneshot},
    task::JoinHandle,
};
use url::Url;

/// Blocks a mock response until released, so a test can observe requests waiting on a refresh.
#[derive(Debug, Clone)]
pub(crate) struct ResponseGate {
    permits: Arc<Semaphore>,
}

impl ResponseGate {
    pub(crate) fn closed() -> Self {
        Self {
            permits: Arc::new(Semaphore::new(0)),
        }
    }

    pub(crate) fn release(&self) {
        self.permits.add_permits(1);
    }

    async fn wait(&self) {
        let permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .unwrap_or_else(|err| panic!("mock response gate closed unexpectedly: {err}"));
        permit.forget();
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MockResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
    gate: Option<ResponseGate>,
}

impl MockResponse {
    pub(crate) fn json(value: &Value) -> Self {
        Self {
            status: StatusCode::OK,
            headers: HeaderMap::from_iter([(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )]),
            body: serde_json::to_vec(value)
                .unwrap_or_else(|err| panic!("mock JSON response must serialize: {err}")),
            gate: None,
        }
    }

    pub(crate) fn text(status: StatusCode, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
            body: body.into(),
            gate: None,
        }
    }

    pub(crate) fn with_gate(mut self, gate: ResponseGate) -> Self {
        self.gate = Some(gate);
        self
    }

    async fn into_response(self) -> Response {
        if let Some(gate) = self.gate {
            gate.wait().await;
        }

        let mut response = Response::new(Body::from(self.body));
        *response.status_mut() = self.status;
        *response.headers_mut() = self.headers;
        response
    }
}

#[derive(Debug)]
struct EndpointState {
    response: Mutex<MockResponse>,
    requests: AtomicUsize,
}

impl EndpointState {
    fn new(response: MockResponse) -> Self {
        Self {
            response: Mutex::new(response),
            requests: AtomicUsize::new(0),
        }
    }

    async fn respond(&self) -> Response {
        self.requests.fetch_add(1, Ordering::Relaxed);
        let response = self.response.lock().await.clone();
        response.into_response().await
    }

    async fn set(&self, response: MockResponse) {
        *self.response.lock().await = response;
    }

    fn request_count(&self) -> usize {
        self.requests.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Clone)]
struct ProviderState {
    discovery: Arc<EndpointState>,
    jwks: Arc<EndpointState>,
}

async fn discovery(State(state): State<ProviderState>) -> Response {
    state.discovery.respond().await
}

async fn jwks(State(state): State<ProviderState>) -> Response {
    state.jwks.respond().await
}

/// The mock provider. Serves an empty JWKS until [`MockOidcServer::set_jwks`] is called, and shuts
/// down when dropped.
#[derive(Debug)]
pub(crate) struct MockOidcServer {
    server_url: Url,
    realm: String,
    state: ProviderState,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<(), std::io::Error>>,
}

impl MockOidcServer {
    pub(crate) async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|err| panic!("mock OIDC listener must bind: {err}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|err| panic!("mock OIDC listener must have an address: {err}"));
        let server_url = Url::parse(&format!("http://{address}/"))
            .unwrap_or_else(|err| panic!("mock OIDC server URL must parse: {err}"));
        let realm = String::from("test-realm");
        let issuer = issuer_url(&server_url, &realm);
        let jwks_url = jwks_url(&server_url);

        let state = ProviderState {
            discovery: Arc::new(EndpointState::new(MockResponse::json(&discovery_document(
                &issuer, &jwks_url,
            )))),
            jwks: Arc::new(EndpointState::new(MockResponse::json(&json!({
                "keys": []
            })))),
        };
        let discovery_path = format!("/realms/{realm}/.well-known/openid-configuration");
        let router = Router::new()
            .route(&discovery_path, get(discovery))
            .route("/jwks", get(jwks))
            .with_state(state.clone());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _result = shutdown_rx.await;
                })
                .await
        });

        Self {
            server_url,
            realm,
            state,
            shutdown: Some(shutdown_tx),
            task,
        }
    }

    pub(crate) fn server_url(&self) -> Url {
        self.server_url.clone()
    }

    pub(crate) fn realm(&self) -> &str {
        &self.realm
    }

    pub(crate) fn discovery_url(&self) -> Url {
        self.server_url
            .join(&format!(
                "realms/{}/.well-known/openid-configuration",
                self.realm
            ))
            .unwrap_or_else(|err| panic!("mock discovery URL must join: {err}"))
    }

    pub(crate) fn jwks_url(&self) -> Url {
        jwks_url(&self.server_url)
    }

    pub(crate) async fn set_discovery_response(&self, response: MockResponse) {
        self.state.discovery.set(response).await;
    }

    /// Serves the regular discovery document again after [`Self::set_discovery_response`].
    pub(crate) async fn restore_discovery_response(&self) {
        let issuer = issuer_url(&self.server_url, &self.realm);
        self.set_discovery_response(MockResponse::json(&discovery_document(
            &issuer,
            &self.jwks_url(),
        )))
        .await;
    }

    pub(crate) async fn set_jwks_response(&self, response: MockResponse) {
        self.state.jwks.set(response).await;
    }

    pub(crate) async fn set_jwks(&self, keys: Vec<Jwk>) {
        self.set_jwks_response(Self::jwks_json(keys)).await;
    }

    /// Replaces the JWKS response with the given keys behind a gate that blocks the response
    /// until released.
    pub(crate) async fn set_gated_jwks(&self, keys: Vec<Jwk>) -> ResponseGate {
        let gate = ResponseGate::closed();
        self.set_jwks_response(Self::jwks_json(keys).with_gate(gate.clone()))
            .await;
        gate
    }

    /// Serves `503 Service Unavailable` for discovery requests until
    /// [`Self::restore_discovery_response`] restores the regular document.
    pub(crate) async fn make_discovery_unavailable(&self) {
        self.set_discovery_response(MockResponse::text(
            StatusCode::SERVICE_UNAVAILABLE,
            "provider unavailable",
        ))
        .await;
    }

    /// Waits until this provider has received at least `expected` JWKS requests.
    pub(crate) async fn wait_for_jwks_requests(&self, expected: usize) {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while self.jwks_requests() < expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the mock provider must receive the expected JWKS requests");
    }

    fn jwks_json(keys: Vec<Jwk>) -> MockResponse {
        let value = serde_json::to_value(JwkSet { keys })
            .unwrap_or_else(|err| panic!("mock JWKS must serialize: {err}"));
        MockResponse::json(&value)
    }

    pub(crate) fn discovery_requests(&self) -> usize {
        self.state.discovery.request_count()
    }

    pub(crate) fn jwks_requests(&self) -> usize {
        self.state.jwks.request_count()
    }
}

impl Drop for MockOidcServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _result = shutdown.send(());
        }
        self.task.abort();
    }
}

fn issuer_url(server_url: &Url, realm: &str) -> Url {
    server_url
        .join(&format!("realms/{realm}"))
        .unwrap_or_else(|err| panic!("mock issuer URL must join: {err}"))
}

fn jwks_url(server_url: &Url) -> Url {
    server_url
        .join("jwks")
        .unwrap_or_else(|err| panic!("mock JWKS URL must join: {err}"))
}

/// A minimal discovery document satisfying the canonical [`crate::oidc::OidcConfig`] contract.
pub(super) fn discovery_document(issuer: &Url, jwks_url: &Url) -> Value {
    let realm_endpoint = |path: &str| {
        Url::parse(&format!("{issuer}/protocol/openid-connect/{path}"))
            .unwrap_or_else(|err| panic!("mock realm endpoint must parse: {err}"))
    };
    json!({
        "issuer": issuer,
        "authorization_endpoint": realm_endpoint("auth"),
        "token_endpoint": realm_endpoint("token"),
        "jwks_uri": jwks_url,
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"]
    })
}
