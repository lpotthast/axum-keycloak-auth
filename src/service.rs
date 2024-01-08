use std::{
    sync::Arc,
    task::{Context, Poll},
};

use axum::{body::Body, response::IntoResponse};
use futures::future::BoxFuture;
use http::Request;

use crate::{
    instance::KeycloakAuthInstance, layer::KeycloakAuthLayer, role::Role, KeycloakAuthStatus,
    PassthroughMode,
};

#[derive(Clone)]
pub struct KeycloakAuthService<S, R: Role> {
    inner: S,
    instance: Arc<KeycloakAuthInstance<R>>,
    passthrough_mode: PassthroughMode,
    persist_raw_claims: bool,
    expected_audiences: Vec<String>,
    required_roles: Vec<R>,
}

impl<S, R: Role> KeycloakAuthService<S, R> {
    pub fn new(inner: S, layer: &KeycloakAuthLayer<R>) -> Self {
        Self {
            inner,
            instance: layer.instance.clone(),
            passthrough_mode: layer.passthrough_mode,
            persist_raw_claims: layer.persist_raw_claims,
            expected_audiences: layer.expected_audiences.clone(), // TODO: not cheap?
            required_roles: layer.required_roles.clone(),         // TODO: not cheap?
        }
    }
}

impl<S, R: Role + 'static> tower::Service<http::Request<axum::body::Body>>
    for KeycloakAuthService<S, R>
where
    S: tower::Service<Request<Body>, Response = axum::response::Response> + Clone + Send + 'static, // TODO: Remove sync bound
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

        // take the service that was ready
        let mut inner = std::mem::replace(&mut self.inner, clone);

        let passthrough_mode = self.passthrough_mode.clone();
        let expected_audiences = self.expected_audiences.clone();
        let persist_raw_claims = self.persist_raw_claims;
        let required_roles = self.required_roles.clone();

        Box::pin(async move {
            match instance
                .process_request(
                    request.headers().clone(),
                    expected_audiences,
                    persist_raw_claims,
                    required_roles,
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
