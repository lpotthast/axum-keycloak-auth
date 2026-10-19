//! An in-process mock OIDC provider: a discovery document and a JWKS endpoint whose responses a
//! test controls (key sets, failures, gated responses), with per-endpoint request counters.
//!
//! Use it to exercise real HTTP discovery. Prefer the offline fixtures in [`super::instances`] and
//! [`super::StaticKeySource`] whenever a test does not need provider I/O.

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

use super::{TEST_REALM, wait_until};

/// Blocks a mock response until released, so a test can observe requests waiting on a refresh.
#[derive(Debug, Clone)]
pub(crate) struct ResponseGate {
    permits: Arc<Semaphore>,
}

impl ResponseGate {
    /// A gate that holds every response until [`Self::release`] is called.
    pub(crate) fn closed() -> Self {
        Self {
            permits: Arc::new(Semaphore::new(0)),
        }
    }

    /// Lets one held response through.
    pub(crate) fn release(&self) {
        self.permits.add_permits(1);
    }

    async fn wait(&self) {
        let permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .expect("the mock response gate must not be closed");
        permit.forget();
    }
}

/// A canned HTTP response served by a [`MockOidcServer`] endpoint.
#[derive(Debug, Clone)]
pub(crate) struct MockResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
    gate: Option<ResponseGate>,
}

impl MockResponse {
    /// `200 OK` with `value` as a JSON body.
    pub(crate) fn json(value: &Value) -> Self {
        Self {
            status: StatusCode::OK,
            headers: HeaderMap::from_iter([(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )]),
            body: serde_json::to_vec(value).expect("a mock JSON response must serialize"),
            gate: None,
        }
    }

    /// `status` with a raw body and no content type.
    pub(crate) fn text(status: StatusCode, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
            body: body.into(),
            gate: None,
        }
    }

    /// Holds this response until `gate` is released.
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

/// The mock provider, serving the realm [`TEST_REALM`] on a random local port. Serves an empty
/// JWKS until [`MockOidcServer::set_jwks`] is called, and shuts down when dropped.
#[derive(Debug)]
pub(crate) struct MockOidcServer {
    server_url: Url,
    realm: String,
    state: ProviderState,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<(), std::io::Error>>,
}

impl MockOidcServer {
    /// Starts serving in a background task of the current Tokio runtime.
    pub(crate) async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("the mock OIDC listener must bind");
        let address = listener
            .local_addr()
            .expect("the mock OIDC listener must have an address");
        let server_url =
            Url::parse(&format!("http://{address}/")).expect("the mock OIDC server URL must parse");
        let realm = String::from(TEST_REALM);
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

    /// The base URL to configure as [`crate::instance::KeycloakConfig::server`].
    pub(crate) fn server_url(&self) -> Url {
        self.server_url.clone()
    }

    /// The served realm name.
    pub(crate) fn realm(&self) -> &str {
        &self.realm
    }

    /// The URL of the realm's discovery document.
    pub(crate) fn discovery_url(&self) -> Url {
        self.server_url
            .join(&format!(
                "realms/{}/.well-known/openid-configuration",
                self.realm
            ))
            .expect("the mock discovery URL must join")
    }

    /// The URL of the realm's JWKS, as advertised by the discovery document.
    pub(crate) fn jwks_url(&self) -> Url {
        jwks_url(&self.server_url)
    }

    /// Replaces the discovery response until the next change.
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

    /// Replaces the JWKS response until the next change.
    pub(crate) async fn set_jwks_response(&self, response: MockResponse) {
        self.state.jwks.set(response).await;
    }

    /// Publishes exactly `keys` as the JWKS.
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
        wait_until(
            &format!("the mock provider must receive {expected} JWKS requests"),
            || self.jwks_requests() >= expected,
        )
        .await;
    }

    fn jwks_json(keys: Vec<Jwk>) -> MockResponse {
        let value = serde_json::to_value(JwkSet { keys }).expect("a mock JWKS must serialize");
        MockResponse::json(&value)
    }

    /// How many discovery requests were received, including gated ones still waiting.
    pub(crate) fn discovery_requests(&self) -> usize {
        self.state.discovery.request_count()
    }

    /// How many JWKS requests were received, including gated ones still waiting.
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
        .expect("the mock issuer URL must join")
}

fn jwks_url(server_url: &Url) -> Url {
    server_url
        .join("jwks")
        .expect("the mock JWKS URL must join")
}

/// A minimal discovery document satisfying the canonical [`crate::oidc::OidcConfig`] contract.
pub(super) fn discovery_document(issuer: &Url, jwks_url: &Url) -> Value {
    let realm_endpoint = |path: &str| {
        Url::parse(&format!("{issuer}/protocol/openid-connect/{path}"))
            .expect("a mock realm endpoint must parse")
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

#[cfg(test)]
mod tests {
    use assertr::prelude::*;
    use axum::http::StatusCode;
    use jsonwebtoken::Algorithm;
    use serde_json::Value;

    use crate::test_support::{RSA_KEY_A, RSA_KEY_B, within_test_timeout};

    use super::{MockOidcServer, MockResponse, ResponseGate};

    async fn get_json(url: url::Url) -> Value {
        reqwest::get(url)
            .await
            .expect("the mock request must succeed")
            .json::<Value>()
            .await
            .expect("the mock response must be JSON")
    }

    #[tokio::test]
    async fn serves_discovery_and_rotating_jwks() {
        let server = MockOidcServer::start().await;
        server
            .set_jwks(vec![RSA_KEY_A.jwk(Some("key-a"), Algorithm::RS256)])
            .await;

        assert_that!(get_json(server.discovery_url()).await)
            .pointer("/jwks_uri")
            .is_equal_to(server.jwks_url().as_str());
        assert_that!(get_json(server.jwks_url()).await)
            .pointer("/keys/0/kid")
            .is_equal_to("key-a");

        server
            .set_jwks(vec![RSA_KEY_B.jwk(Some("key-b"), Algorithm::RS512)])
            .await;
        assert_that!(get_json(server.jwks_url()).await)
            .pointer("/keys/0/kid")
            .is_equal_to("key-b");
        assert_that!(server.discovery_requests()).is_equal_to(1);
        assert_that!(server.jwks_requests()).is_equal_to(2);
    }

    #[tokio::test]
    async fn controls_failures_and_gating() {
        let server = MockOidcServer::start().await;

        server.make_discovery_unavailable().await;
        let failed = reqwest::get(server.discovery_url())
            .await
            .expect("the failure response must be received");
        assert_that!(failed.status()).is_equal_to(StatusCode::SERVICE_UNAVAILABLE);
        server.restore_discovery_response().await;
        let recovered = reqwest::get(server.discovery_url())
            .await
            .expect("the restored response must be received");
        assert_that!(recovered.status()).is_equal_to(StatusCode::OK);

        // A gated response blocks until released.
        let gate = ResponseGate::closed();
        server
            .set_jwks_response(
                MockResponse::text(StatusCode::OK, "malformed-json").with_gate(gate.clone()),
            )
            .await;
        let gated_request = tokio::spawn(reqwest::get(server.jwks_url()));
        server.wait_for_jwks_requests(1).await;
        assert_that!(gated_request.is_finished()).is_false();
        gate.release();
        let gated_response =
            within_test_timeout("the released JWKS request must finish", gated_request)
                .await
                .expect("the gated request task must not panic")
                .expect("the gated request must complete");
        assert_that!(gated_response.text().await)
            .ok()
            .is_equal_to("malformed-json");
    }
}
