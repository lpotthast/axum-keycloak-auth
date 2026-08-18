# axum-keycloak-auth

[![Crates.io](https://img.shields.io/crates/v/axum-keycloak-auth.svg)](https://crates.io/crates/axum-keycloak-auth)
[![Docs.rs](https://docs.rs/axum-keycloak-auth/badge.svg)](https://docs.rs/axum-keycloak-auth)
[![CI](https://github.com/lpotthast/axum-keycloak-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/lpotthast/axum-keycloak-auth/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.89.0-blue.svg)](https://github.com/lpotthast/axum-keycloak-auth/blob/main/Cargo.toml)
[![License: MIT OR Apache-2.0](https://img.shields.io/crates/l/axum-keycloak-auth.svg)](#license)

Protect axum routes with a JWT emitted by Keycloak.

## Features

- Tower layer / service that can be attached to axum routers.
- Automatic OIDC discovery
- Forwarding only requests providing a verifiable and non-expired JWT.
- Ability to allow forwarding a failed authentication attempt to possibly handle the authentication using another
  middleware.
- Ability to access the extracted JWT data (including roles, the KC uuid, ...) in route handler function.
- Tests to check that one or more required or forbidden Keycloak realm or client roles were included in the JWT.
- Ability to access the JWT's raw claims in a handler, allowing to extract custom attributes.
- An error type implementing IntoResponse providing exact information about why authentication failed in an error
  response.
- Ability to define a custom role type from your application to which all roles are automatically parsed.

## Planned

- Ability to provide a custom type into which the token is parsed, with which non-standard JWT claims can be extracted
  without overhead.
- Allowing fine-grained control over how an `AuthError` is converted into a response. Giving the user control and the
  ability to add context, roll their own.

## Usage

This library provides `KeycloakAuthLayer`, a tower layer/service implementation that parses and validates a JWT.

See the **[Documentation](https://docs.rs/axum-keycloak-auth)** for more detailed instructions!

```rust
enum Role {
    Administrator,
    Unknown(String),
}

pub fn protected_router(instance: KeycloakAuthInstance) -> Router {
    Router::new()
        .route("/protected", get(protected))
        .layer(
            KeycloakAuthLayer::<Role>::builder()
                .instance(instance)
                .passthrough_mode(PassthroughMode::Block)
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
            name = token.extra.profile.preferred_username,
            subject = token.subject,
            valid_for = (token.expires_at - time::OffsetDateTime::now_utc()).whole_seconds()
        ),
    ).into_response()
}
```

## Axum compatibility

| axum-keycloak-auth | axum |
|--------------------|------|
| 0.2                | 0.6  |
| 0.3 - 0.6          | 0.7  |
| 0.7 - 0.8          | 0.8  |

## Development

### Tests

Run test with:

```shell
just test
```

### Dependency Security

Run RustSec auditing through:

```shell
just audit
```

No advisories are currently ignored or accepted.

### MSRV

The minimum supported Rust version is 1.89.

## License

This project is licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.
