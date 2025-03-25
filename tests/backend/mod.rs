use axum::{
    response::{IntoResponse, Response}, routing::get, Extension,
    Json,
    Router,
};
use axum_keycloak_auth::{
    decode::KeycloakToken, instance::{KeycloakAuthInstance, KeycloakConfig},
    layer::KeycloakAuthLayer,
    KeycloakAuthStatus,
    PassthroughMode,
};
use http::StatusCode;
use serde::Serialize;
use tokio::{net::TcpListener, task::JoinHandle};
use tower_http::trace::TraceLayer;
use url::Url;

pub async fn start_axum_backend(keycloak_url: Url, realm: String) -> JoinHandle<()> {
    let keycloak_auth_instance = Arc::new(KeycloakAuthInstance::new(
        KeycloakConfig::builder()
            .server(keycloak_url)
            .realm(realm)
            .build(),
    ));

    let router = Router::new()
        .route("/who-am-i", get(who_am_i))
        .layer(TraceLayer::new_for_http())
        .layer(
            KeycloakAuthLayer::<Role, ProfileAndEmail>::builder()
                .instance(keycloak_auth_instance.clone())
                .passthrough_mode(PassthroughMode::Block)
                .expected_audiences(vec![String::from("account")])
                .persist_raw_claims(false)
                .build(),
        );

    // All routes of this router use `PassthroughMode::Pass`.
    // Handlers should inject the `KeycloakAuthStatus` type (as an `axum::Extension`) and
    // manually check whether the request was authenticated!
    let router2 = Router::new()
        .route("/am-i-authenticated", get(am_i_authenticated))
        .layer(TraceLayer::new_for_http())
        .layer(
            KeycloakAuthLayer::<Role, ProfileAndEmail>::builder()
                .instance(keycloak_auth_instance)
                .passthrough_mode(PassthroughMode::Pass)
                .expected_audiences(vec![String::from("account")])
                .persist_raw_claims(false)
                .build(),
        );

    let listener = TcpListener::bind("127.0.0.1:9999")
        .await
        .expect("TcpListener");

    let server_jh = tokio::spawn(async move {
        tracing::info!("Serving test backend...");
        axum::serve(listener, router.merge(router2).into_make_service())
            .await
            .expect("Server to start successfully");
        tracing::info!("Test backend stopped!");
    });

    server_jh
}

#[axum::debug_handler]
pub async fn who_am_i(Extension(token): Extension<KeycloakToken<Role>>) -> Response {
    #[derive(Debug, Serialize)]
    struct Response {
        name: String,
        keycloak_uuid: uuid::Uuid,
        token_valid_for_whole_seconds: i64,
    }

    (
        StatusCode::OK,
        Json(Response {
            name: token.extra.profile.preferred_username,
            keycloak_uuid: uuid::Uuid::try_parse(&token.subject).expect("uuid"),
            token_valid_for_whole_seconds: (token.expires_at - time::OffsetDateTime::now_utc())
                .whole_seconds(),
        }),
    )
        .into_response()
}

#[axum::debug_handler]
pub async fn am_i_authenticated(
    Extension(auth_status): Extension<KeycloakAuthStatus<Role, ProfileAndEmail>>,
) -> Response {
    match auth_status {
        KeycloakAuthStatus::Success(_) => {
            (StatusCode::OK, "You are authenticated.").into_response()
        }
        KeycloakAuthStatus::Failure(_) => {
            (StatusCode::OK, "You are not authenticated.").into_response()
        }
    }
}

use axum_keycloak_auth::decode::ProfileAndEmail;
use std::fmt::Display;
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Role {
    Administrator,
    Unknown(String),
}

impl Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Administrator => f.write_str("Administrator"),
            Role::Unknown(unknown) => f.write_fmt(format_args!("Unknown role: {unknown}")),
        }
    }
}

impl axum_keycloak_auth::role::Role for Role {}

impl From<String> for Role {
    fn from(value: String) -> Self {
        match value.as_ref() {
            "administrator" => Role::Administrator,
            _ => Role::Unknown(value),
        }
    }
}
