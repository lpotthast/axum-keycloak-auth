use std::{fmt::Debug, sync::Arc};
use tower::Layer;
use typed_builder::TypedBuilder;

use crate::{instance::KeycloakAuthInstance, role::Role, service::KeycloakAuthService};

use super::PassthroughMode;

/// Add this layer to a router to protected the contained route handlers.
/// Authentication happens by looking for the `Authorization` header on requests and parsing the contained JWT bearer token.
/// See the crate level documentation for how this layer can be created and used.
#[derive(Clone, TypedBuilder)]
pub struct KeycloakAuthLayer<R: Role> {
    pub instance: Arc<KeycloakAuthInstance<R>>,

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

    #[builder(default = uuid::Uuid::now_v7(), setter(skip))]
    id: uuid::Uuid,
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
    type Service = KeycloakAuthService<S, R>;

    #[tracing::instrument(level="info", skip_all, fields(id = ?self.id))]
    fn layer(&self, inner: S) -> Self::Service {
        KeycloakAuthService::new(inner, self)
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use url::Url;

    use crate::{
        instance::{KeycloakAuthInstance, KeycloakAuthInstanceBuilder},
        layer::KeycloakAuthLayer,
        PassthroughMode,
    };

    #[test]
    fn build_basic_layer() {
        let instance = Arc::new(KeycloakAuthInstance::new(
            KeycloakAuthInstanceBuilder::builder()
                .server(Url::parse("https://localhost:8443/").unwrap())
                .realm(String::from("MyRealm"))
                .build(),
        ));

        let _layer = KeycloakAuthLayer::<String>::builder()
            .instance(instance)
            .passthrough_mode(PassthroughMode::Block)
            .expected_audiences(vec![String::from("account")])
            .build();
    }

    #[test]
    fn build_full_layer() {
        let instance = Arc::new(KeycloakAuthInstance::new(
            KeycloakAuthInstanceBuilder::builder()
                .server(Url::parse("https://localhost:8443/").unwrap())
                .realm(String::from("MyRealm"))
                .build(),
        ));

        let _layer = KeycloakAuthLayer::<String>::builder()
            .instance(instance)
            .passthrough_mode(PassthroughMode::Block)
            .persist_raw_claims(false)
            .expected_audiences(vec![String::from("account")])
            .required_roles(vec![String::from("administrator")])
            .build();
    }
}
