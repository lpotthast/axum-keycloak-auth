use nonempty::NonEmpty;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::{fmt::Debug, sync::Arc};
use tower::Layer;
use typed_builder::TypedBuilder;

use crate::decode::{
    decode_and_validate, parse_raw_claims, KeycloakToken, ProfileAndEmail, RawToken,
};
use crate::error::AuthError;
use crate::extract::TokenExtractor;
use crate::{instance::KeycloakAuthInstance, role::Role, service::KeycloakAuthService};

use super::PassthroughMode;

extern crate alloc;

/// Add this layer to a router to protect the contained route handlers.
/// Authentication happens by looking for the `Authorization` header on requests and parsing the contained JWT bearer token.
/// See the crate level documentation for how this layer can be created and used.
#[derive(Clone, TypedBuilder)]
pub struct KeycloakAuthLayer<R, Extra = ProfileAndEmail>
where
    R: Role,
    Extra: DeserializeOwned + Clone,
{
    #[builder(setter(into))]
    pub instance: Arc<KeycloakAuthInstance>,

    /// See `PassthroughMode` for more information.
    #[builder(default = PassthroughMode::Block)]
    pub passthrough_mode: PassthroughMode,

    /// Determine if the raw claims extracted from the JWT are persisted as an `Extension`.
    /// If you do not need access to this information, fell free to set this to false.
    #[builder(default = false)]
    pub persist_raw_claims: bool,

    /// Allowed values of the JWT 'aud' (audiences) field. Token validation will fail immediately if this is left empty!
    pub expected_audiences: Vec<String>,

    /// These roles are always required.
    /// Should a route protected by this layer be accessed by a user not having this role, an error is generated.
    /// If fine-grained role-based access management in required,
    /// leave this empty and perform manual role checks in your route handlers.
    #[builder(default = vec![], setter(into))]
    pub required_roles: Vec<R>,

    /// Specifies where the token is expected to be found.
    #[builder(default = nonempty::nonempty![Arc::new(crate::extract::AuthHeaderTokenExtractor {})])]
    pub token_extractors: NonEmpty<Arc<dyn TokenExtractor>>,

    #[builder(default = uuid::Uuid::now_v7(), setter(skip))]
    id: uuid::Uuid,

    #[builder(default=PhantomData, setter(skip))]
    phantom: PhantomData<Extra>,
}

impl<R, Extra> KeycloakAuthLayer<R, Extra>
where
    R: Role,
    Extra: DeserializeOwned + Clone,
{
    /// Allows to validate a raw keycloak token given as &str (without the "Bearer " part when taken from an authorization header).
    /// This method is helpful if you wish to validate a token which does not pass the axum middleware
    /// or if you wish to validate a token in a different context.
    pub async fn validate_raw_token(
        &self,
        raw_token: &str,
    ) -> Result<
        (
            Option<HashMap<String, serde_json::Value>>,
            KeycloakToken<R, Extra>,
        ),
        AuthError,
    > {
        let raw_claims = decode_and_validate(
            self.instance.as_ref(),
            RawToken(raw_token),
            &self.expected_audiences,
        )
        .await?;

        parse_raw_claims::<R, Extra>(raw_claims, self.persist_raw_claims, &self.required_roles)
            .await
    }
}

impl<R, Extra> Debug for KeycloakAuthLayer<R, Extra>
where
    R: Role,
    Extra: DeserializeOwned + Clone,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeycloakAuthLayer")
            .field("mode", &self.passthrough_mode)
            .field("persist_raw_claims", &self.persist_raw_claims)
            .finish()
    }
}

impl<S, R, Extra> Layer<S> for KeycloakAuthLayer<R, Extra>
where
    R: Role,
    Extra: DeserializeOwned + Clone,
{
    type Service = KeycloakAuthService<S, R, Extra>;

    #[tracing::instrument(level="info", skip_all, fields(id = ?self.id))]
    fn layer(&self, inner: S) -> Self::Service {
        KeycloakAuthService::new(inner, self)
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use nonempty::NonEmpty;
    use url::Url;

    use crate::{
        extract::{AuthHeaderTokenExtractor, QueryParamTokenExtractor, TokenExtractor},
        instance::{KeycloakAuthInstance, KeycloakConfig},
        layer::KeycloakAuthLayer,
        PassthroughMode,
    };

    #[tokio::test]
    async fn build_basic_layer() {
        let instance = KeycloakAuthInstance::new(
            KeycloakConfig::builder()
                .server(Url::parse("https://localhost:8443/").unwrap())
                .realm(String::from("MyRealm"))
                .retry((10, 2))
                .build(),
        );

        let _layer = KeycloakAuthLayer::<String>::builder()
            .instance(instance)
            .passthrough_mode(PassthroughMode::Block)
            .expected_audiences(vec![String::from("account")])
            .build();
    }

    #[tokio::test]
    async fn build_full_layer() {
        let instance = KeycloakAuthInstance::new(
            KeycloakConfig::builder()
                .server(Url::parse("https://localhost:8443/").unwrap())
                .realm(String::from("MyRealm"))
                .retry((10, 2))
                .build(),
        );

        let _layer = KeycloakAuthLayer::<String>::builder()
            .instance(instance)
            .passthrough_mode(PassthroughMode::Block)
            .persist_raw_claims(false)
            .expected_audiences(vec![String::from("account")])
            .required_roles(vec![String::from("administrator")])
            .token_extractors(NonEmpty::<Arc<dyn TokenExtractor>> {
                head: Arc::new(AuthHeaderTokenExtractor::default()),
                tail: vec![
                    Arc::new(QueryParamTokenExtractor::default()),
                    Arc::new(QueryParamTokenExtractor::extracting_key("jwt")),
                ],
            })
            .build();
    }
}
