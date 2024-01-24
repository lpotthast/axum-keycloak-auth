use std::{
    collections::HashMap,
    sync::Arc,
    task::{Context, Poll},
};

use axum::{body::Body, response::IntoResponse};
use futures::future::BoxFuture;
use http::Request;

use crate::{
    decode::{extract_jwt_token, KeycloakToken, StandardClaims},
    error::AuthError,
    instance::KeycloakAuthInstance,
    layer::KeycloakAuthLayer,
    role::{ExpectRoles, Role},
    KeycloakAuthStatus, PassthroughMode,
};

#[derive(Clone)]
pub struct KeycloakAuthService<S, R: Role> {
    inner: S,
    instance: Arc<KeycloakAuthInstance>,
    passthrough_mode: PassthroughMode,
    persist_raw_claims: bool,
    expected_audiences: Arc<Vec<String>>,
    required_roles: Arc<Vec<R>>,
}

impl<S, R: Role> KeycloakAuthService<S, R> {
    pub fn new(inner: S, layer: &KeycloakAuthLayer<R>) -> Self {
        Self {
            inner,
            instance: layer.instance.clone(),
            passthrough_mode: layer.passthrough_mode,
            persist_raw_claims: layer.persist_raw_claims,
            expected_audiences: Arc::new(layer.expected_audiences.clone()),
            required_roles: Arc::new(layer.required_roles.clone()),
        }
    }
}

impl<S, R: Role + 'static> tower::Service<http::Request<axum::body::Body>>
    for KeycloakAuthService<S, R>
where
    S: tower::Service<Request<Body>, Response = axum::response::Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match (self.instance.is_ready(), self.inner.poll_ready(cx)) {
            (true, Poll::Ready(t)) => Poll::Ready(t),
            (false, _) => Poll::Pending,
            (_, Poll::Pending) => Poll::Pending,
        }
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        let clone = self.inner.clone();
        let instance = self.instance.clone();

        // Take the service that was ready!
        let mut inner = std::mem::replace(&mut self.inner, clone);

        let passthrough_mode = self.passthrough_mode;
        let persist_raw_claims = self.persist_raw_claims;
        let expected_audiences = self.expected_audiences.clone();
        let required_roles = self.required_roles.clone();

        Box::pin(async move {
            match process_request(
                &instance,
                request.headers().clone(),
                expected_audiences.as_slice(),
                persist_raw_claims,
                required_roles.as_slice(),
            )
            .await
            {
                Ok((raw_claims, keycloak_token)) => {
                    if let Some(raw_claims) = raw_claims {
                        request.extensions_mut().insert(raw_claims);
                    }
                    match passthrough_mode {
                        PassthroughMode::Block => {
                            request.extensions_mut().insert(keycloak_token);
                        }
                        PassthroughMode::Pass => {
                            request
                                .extensions_mut()
                                .insert(KeycloakAuthStatus::<R>::Success(keycloak_token));
                        }
                    };
                    inner.call(request).await
                }
                Err(err) => match passthrough_mode {
                    PassthroughMode::Block => Ok(err.into_response()),
                    PassthroughMode::Pass => {
                        request
                            .extensions_mut()
                            .insert(KeycloakAuthStatus::<R>::Failure(Arc::new(err)));
                        inner.call(request).await
                    }
                },
            }
        })
    }
}

pub(crate) async fn process_request<R: Role>(
    kc_instance: &KeycloakAuthInstance,
    request_headers: http::HeaderMap<http::HeaderValue>,
    expected_audiences: &[String],
    persist_raw_claims: bool,
    required_roles: &[R],
) -> Result<(Option<HashMap<String, serde_json::Value>>, KeycloakToken<R>), AuthError> {
    let raw_token = extract_jwt_token(&request_headers)?;
    let header = raw_token.decode_header()?;

    // First decode. This may fail if known decoding keys are out of date (Keycloak server changed).
    let decoding_keys = kc_instance.decoding_keys().await;
    let mut raw_claims = raw_token.decode(&header, expected_audiences, decoding_keys.iter());

    if raw_claims.is_err() {
        // TODO: Match error and only retry on specific error variants!
        // match raw_claims.unwrap_err() {
        //     AuthError::Decode { source } => todo!(),
        // }

        // TODO: Only retry if not throttled!

        // Reload decoding keys. Note that this will delay handling of the request in flight by a substantial amount of time
        // but may allow us to acknowledge it in the end without rejecting the call immediately, which would then require a retry from our callers!
        // TODO: Make this an optional behavior.
        kc_instance
            .discovery
            .dispatch(kc_instance.oidc_discovery_endpoint.clone())
            .await
            .expect("No Join error");

        // Second decode
        let decoding_keys = kc_instance.decoding_keys().await;
        raw_claims = raw_token.decode(&header, expected_audiences, decoding_keys.iter());
    }

    let raw_claims = raw_claims?;

    let raw_claims_clone = match persist_raw_claims {
        true => Some(raw_claims.clone()),
        false => None,
    };
    let standard_claims = StandardClaims::parse(raw_claims)?;
    let keycloak_token = KeycloakToken::<R>::parse(standard_claims)?;
    keycloak_token.assert_not_expired()?;
    keycloak_token.expect_roles(required_roles)?;
    Ok((raw_claims_clone, keycloak_token))
}
