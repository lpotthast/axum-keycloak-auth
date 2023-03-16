use std::{
    fmt::Debug,
    marker::PhantomData,
    sync::Arc,
    task::{Context, Poll},
};

use axum::{
    body::Body,
    http::Request,
    response::{IntoResponse, Response},
};
use futures::future::BoxFuture;
use jsonwebtoken::DecodingKey;
use tower::{Layer, Service};
use typed_builder::TypedBuilder;

use crate::{
    decode::{parse_jwt_token, KeycloakToken, StandardClaims},
    role::{Role, ExpectRoles},
};

use super::{KeycloakAuthStatus, PassthroughMode};

/// Add this layer to a router to protected the contained route handlers.
/// Authentication happens by looking for the `Authorization` header on requests and parsing the contained JWT bearer token.
/// See the crate level documentation for how this layer can be created and used.
#[derive(Clone, TypedBuilder)]
pub struct KeycloakAuthLayer<R: Role> {
    /// JWT's are signed. For checking this signature, a `jsonwebtoken::DecodingKey` is required.
    /// You may construct this using the public key of the Keycloak realm which is going to sign tokens used for requests.
    pub decoding_key: Arc<DecodingKey>,

    /// See `PassthroughMode` for more information.
    #[builder(default = PassthroughMode::Block)]
    pub passthrough_mode: PassthroughMode,

    /// Determine if the raw claims extracted from the JWT are persisted as an `Extension`.
    /// If you do not need access to this information, fell free to set this to false.
    #[builder(default = false)]
    pub persist_raw_claims: bool,

    /// These roles are always required.
    /// Should a route protected by this layer be accessed by a user not having this role, an error is generated.
    #[builder(default = vec![])]
    pub required_roles: Vec<R>,

    #[builder(default, setter(skip))]
    pub phantom_data: PhantomData<R>,
}

impl<R: Role> Debug for KeycloakAuthLayer<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeycloakAuthLayer")
            .field("mode", &self.passthrough_mode)
            .field("persist_raw_claims", &self.persist_raw_claims)
            .finish()
    }
}

impl<S, R: Role> Layer<S> for KeycloakAuthLayer<R> {
    type Service = KeycloakAuthMiddleware<S, R>;

    fn layer(&self, inner: S) -> Self::Service {
        KeycloakAuthMiddleware {
            inner,
            mode: self.passthrough_mode,
            persist_raw_claims: self.persist_raw_claims,
            jwt_decoding_key: self.decoding_key.clone(),
            required_roles: self.required_roles.clone(),
            phantom_data: PhantomData,
        }
    }
}

#[derive(Clone)]
pub struct KeycloakAuthMiddleware<S, R: Role> {
    inner: S,
    mode: PassthroughMode,
    persist_raw_claims: bool,
    jwt_decoding_key: Arc<DecodingKey>,
    required_roles: Vec<R>,
    phantom_data: PhantomData<R>,
}

impl<S, R: Role + 'static> Service<Request<Body>> for KeycloakAuthMiddleware<S, R>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Our middleware doesn't care about backpressure so its ready as long as the inner service is ready.
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        let mut this = self.clone();

        Box::pin(async move {
            match parse_jwt_token(request.headers())
                .and_then(|token| token.decode(&this.jwt_decoding_key))
                .and_then(|raw_claims| {
                    let raw_claims_clone = match this.persist_raw_claims {
                        true => Some(raw_claims.clone()),
                        false => None,
                    };
                    let standard_claims = StandardClaims::parse(raw_claims)?;
                    let keycloak_token = KeycloakToken::<R>::parse(standard_claims)?;
                    keycloak_token.assert_not_expired()?;
                    keycloak_token.expect_roles(&this.required_roles)?;
                    Ok((raw_claims_clone, keycloak_token))
                }) {
                Ok((raw_claims, keycloak_token)) => {
                    if let Some(raw_claims) = raw_claims {
                        request.extensions_mut().insert(raw_claims);
                    }
                    match this.mode {
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
                Err(err) => match this.mode {
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
