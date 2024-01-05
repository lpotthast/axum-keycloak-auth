use std::{
    sync::Arc,
    task::{Context, Poll},
};

use axum::{body::Body, response::IntoResponse};
use futures::future::BoxFuture;
use http::Request;

use crate::{
    layer::KeycloakAuthLayer, role::Role, service::KeycloakAuthService, KeycloakAuthStatus,
    PassthroughMode,
};

#[derive(Clone)]
pub struct KeycloakAuthMiddleware<S, R: Role> {
    inner: S,
    service: Arc<KeycloakAuthService<R>>,
}

impl<S, R: Role> KeycloakAuthMiddleware<S, R> {
    pub fn new(inner: S, layer: &KeycloakAuthLayer<R>) -> Self {
        Self {
            inner,
            service: Arc::new(KeycloakAuthService::new(layer)),
        }
    }
}

impl<S, R: Role + 'static> tower::Service<http::Request<axum::body::Body>>
    for KeycloakAuthMiddleware<S, R>
where
    S: tower::Service<Request<Body>, Response = axum::response::Response> + Clone + Send + 'static, // TODO: Remove sync bound
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match (self.service.is_ready(), self.inner.poll_ready(cx)) {
            (true, Poll::Ready(t)) => Poll::Ready(t),
            (false, _) => Poll::Pending,
            (_, Poll::Pending) => Poll::Pending,
        }
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        let mut this = self.clone();

        Box::pin(async move {
            match this
                .service
                .process_request(request.headers().clone())
                .await
            {
                Ok((raw_claims, keycloak_token)) => {
                    if let Some(raw_claims) = raw_claims {
                        request.extensions_mut().insert(raw_claims);
                    }
                    match this.service.mode {
                        PassthroughMode::Block => {
                            request.extensions_mut().insert(keycloak_token);
                        }
                        PassthroughMode::Pass => {
                            request
                                .extensions_mut()
                                .insert(KeycloakAuthStatus::<R>::Success(keycloak_token));
                        }
                    };
                    this.inner.call(request).await
                }
                Err(err) => match this.service.mode {
                    PassthroughMode::Block => Ok(err.into_response()),
                    PassthroughMode::Pass => {
                        request
                            .extensions_mut()
                            .insert(KeycloakAuthStatus::<R>::Failure(Arc::new(err)));
                        this.inner.call(request).await
                    }
                },
            }
        })
    }
}
