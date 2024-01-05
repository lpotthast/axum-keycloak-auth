use std::{fmt::Debug, marker::PhantomData, ops::Deref};
use tower::Layer;
use typed_builder::TypedBuilder;
use url::Url;

use crate::{middleware::KeycloakAuthMiddleware, role::Role};

use super::PassthroughMode;

/// Add this layer to a router to protected the contained route handlers.
/// Authentication happens by looking for the `Authorization` header on requests and parsing the contained JWT bearer token.
/// See the crate level documentation for how this layer can be created and used.
#[derive(Clone, TypedBuilder)]
pub struct KeycloakAuthLayer<R: Role> {
    pub server: Url,

    pub realm: String,

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
        KeycloakAuthMiddleware::new(inner, self)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct OidcDiscoveryEndpoint(pub(crate) Url);

impl OidcDiscoveryEndpoint {
    pub(crate) fn from_server_and_realm(server: Url, realm: &str) -> Self {
        let mut url = server;
        url.path_segments_mut()
            .expect("to allow path segments on Keycloak server url")
            .extend(&["realms", &realm, ".well-known", "openid-configuration"]);
        Self(url)
    }
}

impl Deref for OidcDiscoveryEndpoint {
    type Target = Url;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod test {
    use url::Url;

    use crate::{layer::KeycloakAuthLayer, PassthroughMode};

    #[test]
    fn build_basic_layer() {
        let _layer = KeycloakAuthLayer::<String>::builder()
            .server(Url::parse("https://localhost:8443/").unwrap())
            .realm(String::from("MyRealm"))
            .passthrough_mode(PassthroughMode::Block)
            .expected_audiences(vec![String::from("account")])
            .build();
    }

    #[test]
    fn build_full_layer() {
        let _layer = KeycloakAuthLayer::<String>::builder()
            .server(Url::parse("https://localhost:8443/").unwrap())
            .realm(String::from("MyRealm"))
            .passthrough_mode(PassthroughMode::Block)
            .persist_raw_claims(false)
            .expected_audiences(vec![String::from("account")])
            .required_roles(vec![String::from("administrator")])
            .build();
    }
}
