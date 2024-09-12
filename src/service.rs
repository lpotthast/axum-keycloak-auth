use std::{
    sync::Arc,
    task::{Context, Poll},
};

use axum::{body::Body, response::IntoResponse};
use futures::future::BoxFuture;
use http::Request;
use serde::de::DeserializeOwned;

use crate::{
    error::AuthError, extract, layer::KeycloakAuthLayer, role::Role, KeycloakAuthStatus,
    PassthroughMode,
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

impl<S, R, Extra> tower::Service<Request<Body>> for KeycloakAuthService<S, R, Extra>
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
        // Once ready, we shall always be ready, independent of future discovery requests,
        // satisfying a `poll_ready` requirement!
        let is_ready = self.layer.instance.discovery.version() > 0;

        if is_ready {
            tracing::debug!("Ready to process requests.");
        } else {
            tracing::debug!("Not ready to process requests. Waiting for initial discovery...");

            // We have to assume that the discovery action was initialized.
            // Our waker handling in would otherwise be wrong!
            assert!(self.layer.instance.discovery.is_pending());
            let instance = self.layer.instance.clone();
            let waker = cx.waker().clone();
            tokio::spawn(async move {
                instance.discovery.notified().await;
                waker.wake();
            });
        }

        match (is_ready, self.inner.poll_ready(cx)) {
            (true, Poll::Ready(t)) => Poll::Ready(t),
            (false, _) => Poll::Pending,
            (_, Poll::Pending) => Poll::Pending,
        }
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        tracing::debug!("Validating request...");

        let clone = self.inner.clone();
        let cloned_layer = self.layer.clone();

        // Take the service that was ready!
        let mut inner = std::mem::replace(&mut self.inner, clone);

        let passthrough_mode = cloned_layer.passthrough_mode;

        Box::pin(async move {
            // Process the request.
            let result = match extract::extract_jwt(&request, &cloned_layer.token_extractors) {
                Some(token) => cloned_layer.validate_raw_token(&token).await,
                None => Err(AuthError::MissingToken),
            };

            match result {
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
