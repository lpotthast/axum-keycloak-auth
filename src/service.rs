use std::{
    collections::HashMap,
    marker::PhantomData,
    sync::Arc,
    task::{Context, Poll},
};

use axum::{body::Body, response::IntoResponse};
use futures::future::BoxFuture;
use http::Request;
use serde::de::DeserializeOwned;

use crate::{
    decode::{extract_jwt_token, KeycloakToken},
    error::AuthError,
    instance::KeycloakAuthInstance,
    layer::KeycloakAuthLayer,
    role::{ExpectRoles, Role},
    KeycloakAuthStatus, PassthroughMode,
};

#[derive(Clone)]
pub struct KeycloakAuthService<S, R, Extra>
where
    R: Role,
    Extra: DeserializeOwned,
{
    inner: S,
    instance: Arc<KeycloakAuthInstance>,
    passthrough_mode: PassthroughMode,
    persist_raw_claims: bool,
    expected_audiences: Arc<Vec<String>>,
    required_roles: Arc<Vec<R>>,
    phantom: PhantomData<Extra>,
}

impl<S, R, Extra> KeycloakAuthService<S, R, Extra>
where
    R: Role,
    Extra: DeserializeOwned + Clone,
{
    pub fn new(inner: S, layer: &KeycloakAuthLayer<R, Extra>) -> Self {
        Self {
            inner,
            instance: layer.instance.clone(),
            passthrough_mode: layer.passthrough_mode,
            persist_raw_claims: layer.persist_raw_claims,
            expected_audiences: Arc::new(layer.expected_audiences.clone()),
            required_roles: Arc::new(layer.required_roles.clone()),
            phantom: PhantomData,
        }
    }
}

impl<S, R, Extra> tower::Service<http::Request<axum::body::Body>>
    for KeycloakAuthService<S, R, Extra>
where
    S: tower::Service<Request<Body>, Response = axum::response::Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    R: Role + 'static,
    Extra: DeserializeOwned + Clone + Sync + Send + 'static,
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
                                .insert(KeycloakAuthStatus::<R, Extra>::Success(keycloak_token));
                        }
                    };
                    inner.call(request).await
                }
                Err(err) => match passthrough_mode {
                    PassthroughMode::Block => Ok(err.into_response()),
                    PassthroughMode::Pass => {
                        request
                            .extensions_mut()
                            .insert(KeycloakAuthStatus::<R, Extra>::Failure(Arc::new(err)));
                        inner.call(request).await
                    }
                },
            }
        })
    }
}

pub(crate) async fn process_request<R, Extra>(
    kc_instance: &KeycloakAuthInstance,
    request_headers: http::HeaderMap<http::HeaderValue>,
    expected_audiences: &[String],
    persist_raw_claims: bool,
    required_roles: &[R],
) -> Result<
    (
        Option<HashMap<String, serde_json::Value>>,
        KeycloakToken<R, Extra>,
    ),
    AuthError,
>
where
    R: Role,
    Extra: DeserializeOwned + Clone,
{
    let raw_token = extract_jwt_token(&request_headers)?;
    let header = raw_token.decode_header()?;

    // First decode. This may fail if known decoding keys are out of date (Keycloak server changed).
    let mut raw_claims = {
        let decoding_keys = kc_instance.decoding_keys().await;
        raw_token.decode(&header, expected_audiences, decoding_keys.iter())
    };

    if raw_claims.is_err() {
        // Reload decoding keys. This may delay handling of the request in flight by a substantial amount of time
        // but may allow us to acknowledge it in the end without rejecting the call immediately,
        // which would then require a retry from our caller!
        #[allow(clippy::unwrap_used)]
        let retry = match raw_claims.as_ref().unwrap_err() {
            AuthError::NoDecodingKeys | AuthError::Decode { source: _ } => {
                if kc_instance.discovery.is_pending() {
                    kc_instance.discovery.notified().await;
                } else {
                    kc_instance
                        .discovery
                        .dispatch(kc_instance.oidc_discovery_endpoint.clone())
                        .await
                        .expect("No Join error");
                }
                true
            }
            _ => false,
        };

        // Second decode
        if retry {
            let decoding_keys = kc_instance.decoding_keys().await;
            raw_claims = raw_token.decode(&header, expected_audiences, decoding_keys.iter());
        }
    }

    let raw_claims = raw_claims?;

    let raw_claims_clone = match persist_raw_claims {
        true => Some(raw_claims.clone()),
        false => None,
    };
    let value = serde_json::Value::from_iter(raw_claims.into_iter());

    let standard_claims = serde_json::from_value(value).map_err(|err| AuthError::JsonParse {
        source: Arc::new(err),
    })?;
    let keycloak_token = KeycloakToken::<R, Extra>::parse(standard_claims)?;
    keycloak_token.assert_not_expired()?;
    keycloak_token.expect_roles(required_roles)?;
    Ok((raw_claims_clone, keycloak_token))
}
