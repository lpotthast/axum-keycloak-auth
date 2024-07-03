use axum::{
    response::{IntoResponse, Response},
    routing::get,
    Extension, Json, Router,
};
use axum_keycloak_auth::{
    decode::KeycloakToken,
    instance::{KeycloakAuthInstance, KeycloakConfig},
    layer::KeycloakAuthLayer,
    PassthroughMode,
};
use http::StatusCode;
use serde::Serialize;
use tokio::{net::TcpListener, task::JoinHandle};
use tower_http::trace::TraceLayer;
use url::Url;

pub async fn start_axum_backend(keycloak_url: Url, realm: String) -> JoinHandle<()> {
    let keycloak_auth_instance = KeycloakAuthInstance::new(
        KeycloakConfig::builder()
            .server(keycloak_url)
            .realm(realm)
            .build(),
    );

    let router = Router::new().route("/who-am-i", get(who_am_i))
    .layer(TraceLayer::new_for_http())
    .layer(
        KeycloakAuthLayer::<String>::builder()
            .instance(keycloak_auth_instance)
            .passthrough_mode(PassthroughMode::Block)
            .expected_audiences(vec![String::from("account")])
            .persist_raw_claims(false)
            .build(),
    );

    let listener = TcpListener::bind("127.0.0.1:9999")
        .await
        .expect("TcpListener");

    let server_jh = tokio::spawn(async move {
        tracing::info!("Serving test backend...");
        axum::serve(listener, router.into_make_service())
            .await
            .expect("Server to start successfully");
        tracing::info!("Test backend stopped!");
    });

    server_jh
}

pub async fn who_am_i(Extension(token): Extension<KeycloakToken<String>>) -> Response {
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
