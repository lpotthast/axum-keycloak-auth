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
    role::{ExpectRoles, Role},
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

    /// Allowed values of the JWT 'aud' field. Token validation will fail immediately if this is left empty!
    pub expected_audiences: Vec<String>,

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
            expected_audiences: self.expected_audiences.clone(),
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
    expected_audiences: Vec<String>,
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
                .and_then(|token| token.decode(&this.jwt_decoding_key, this.expected_audiences.as_slice()))
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

#[cfg(test)]
mod test {
    use jsonwebtoken::DecodingKey;
    use std::sync::Arc;

    use crate::{service::KeycloakAuthLayer, PassthroughMode};

    #[test]
    fn build_basic_layer() {
        let _layer = KeycloakAuthLayer::<String>::builder()
            .decoding_key(Arc::new(create_decoding_key()))
            .passthrough_mode(PassthroughMode::Block)
            .expected_audiences(vec![String::from("account")])
            .build();
    }

    #[test]
    fn build_full_layer() {
        let _layer = KeycloakAuthLayer::<String>::builder()
            .decoding_key(Arc::new(create_decoding_key()))
            .passthrough_mode(PassthroughMode::Block)
            .persist_raw_claims(false)
            .expected_audiences(vec![String::from("account")])
            .required_roles(vec![String::from("administrator")])
            .build();
    }

    fn create_decoding_key() -> DecodingKey {
        const PUBLIC_KEY_PEM: &str = r#"
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv1+Qqa8AgodwBjYQzX0mvY4l9XUQzxNgg5wOutcnRZNNiMjdA8wsP33pYj7hY07xaI4ff3Oc7XMXqKkSXF0+xDEYC2hRuqknfpZzkbH5hvGn3t970zIlguqWUy/zWyy+xT/Wn1m2eWgtjGB2PO4Z1xnT3p26h1tbOoi8Yr8pecGQH2GyFsrXQI5QzXk4XVMdMWIe1xIVzEmZnnizPt0+ACv7J3Z3bMpUFb7m3qxM5uA/hg3LWbozVxj61+T2L5JQXxKzJFTfzBV1M73cLFmTwrEPzyTZNSZj6ug/9q2v+S4laRQA7InxbFAvXJU5oKIqW9qTGLpYDEV/XayhA+ESZwIDAQAB
        -----END PUBLIC KEY-----
        "#;
        DecodingKey::from_rsa_pem(PUBLIC_KEY_PEM.as_bytes()).expect("valid key input")
    }
}
