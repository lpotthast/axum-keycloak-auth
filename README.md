# axum-keycloak-auth

Protect axum routes with a JWT emitted by Keycloak.

## Features

- Tower layer / service that can be attached to axum routers.
- Forwarding only requests providing a verifiable and non-expired JWT.
- Ability to allow forwarding a failed authentication attempt to possibly handle the authentication using another middleware.
- Ability to access the extracted JWT data (including roles, the KC uuid, ...) in route handler function.
- Tests to check that one or more required or forbidden Keycloak realm or client roles were included in the JWT.
- Ability to access the JWT's raw claims in a handler, allowing to extract custom attributes.
- An error type implementing IntoResponse providing exact information about why authentication failed in an error response.
- Ability to define a custom role type from your application to which all roles are automatically parsed.

## Planned

- OIDC-discovery as done in [leptos-keycloak-auth](https://docs.rs/leptos-keycloak-auth) with automated JWK retrieval.
- Ability to provide a custom type into which the token is parsed, with which non-standard JWT claims can be extracted without overhead.
- Allowing fine-grained control over how an `AuthError` is converted into a response. Giving the user control and the ability to add context, roll their own.

## Usage

This library provides `KeycloakAuthLayer`, a tower layer/service implementation that parses and validates a JWT.

Note that this is an extremely abbreviated example.

See the **[Documentation](https://docs.rs/axum-keycloak-auth)** for detailed instructions.

```rust
enum Role {
    Administrator,
    Unknown(String),
}

pub fn protected_router(decoding_key: Arc<DecodingKey>) -> Router {
    Router::new()
        .route("/protected", get(protected))
        .layer(
             KeycloakAuthLayer::<Role>::builder()
                 .decoding_key(decoding_key)
                 .passthrough_mode(PassthroughMode::Block)
                 .persist_raw_claims(false)
                 .build(),
        )
}

pub async fn protected(Extension(token): Extension<KeycloakToken<Role>>) -> Response {
    expect_role!(&token, Role::Administrator);

    info!("Token payload is {token:#?}");
    (
        StatusCode::OK,
        format!(
            "Hello {name} ({subject}). Your token is valid for another {valid_for} seconds.",
            name = token.full_name,
            subject = token.subject,
            valid_for = (token.expires_at - time::OffsetDateTime::now_utc()).whole_seconds()
        ),
    ).into_response()
}
```

## Axum compatibility

| axum | axum-keycloak-auth |
| ---- | ------------------ |
| 0.6  | 0.2                |
| 0.7  | 0.3                |
