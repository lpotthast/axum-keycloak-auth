use std::{
    collections::HashMap,
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
    layer::KeycloakAuthLayer,
    role::Role,
    KeycloakAuthStatus, PassthroughMode,
};

#[derive(Clone)]
pub struct KeycloakAuthService<S, R, Extra>
where
    R: Role,
    Extra: DeserializeOwned + Clone,
{
    inner: S,
    layer: KeycloakAuthLayer<R, Extra>,
}

impl<S, R, Extra> KeycloakAuthService<S, R, Extra>
where
    R: Role,
    Extra: DeserializeOwned + Clone,
{
    pub fn new(inner: S, layer: &KeycloakAuthLayer<R, Extra>) -> Self {
        Self {
            inner,
            layer: layer.clone(),
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
        match (self.layer.instance.is_ready(), self.inner.poll_ready(cx)) {
            (true, Poll::Ready(t)) => Poll::Ready(t),
            (false, _) => Poll::Pending,
            (_, Poll::Pending) => Poll::Pending,
        }
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        let clone = self.inner.clone();
        let cloned_layer = self.layer.clone();

        // Take the service that was ready!
        let mut inner = std::mem::replace(&mut self.inner, clone);

        let passthrough_mode = cloned_layer.passthrough_mode;

        Box::pin(async move {
            match process_request(&cloned_layer, request.headers().clone()).await {
                Ok((raw_claims, keycloak_token)) => {
                    if let Some(raw_claims) = raw_claims {
                        request.extensions_mut().insert(raw_claims);
                    }
                    match cloned_layer.passthrough_mode {
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

async fn process_request<R, Extra>(
    kc_layer: &KeycloakAuthLayer<R, Extra>,
    request_headers: http::HeaderMap<http::HeaderValue>,
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
    let raw_token_str = extract_jwt_token(&request_headers)?;
    kc_layer.validate_raw_token(raw_token_str).await
}
