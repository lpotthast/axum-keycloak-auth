# axum-keycloak-auth

[![Crates.io](https://img.shields.io/crates/v/axum-keycloak-auth.svg)](https://crates.io/crates/axum-keycloak-auth)
[![Docs.rs](https://docs.rs/axum-keycloak-auth/badge.svg)](https://docs.rs/axum-keycloak-auth)
[![CI](https://github.com/lpotthast/axum-keycloak-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/lpotthast/axum-keycloak-auth/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.89.0-blue.svg)](https://github.com/lpotthast/axum-keycloak-auth/blob/main/Cargo.toml)
[![License: MIT OR Apache-2.0](https://img.shields.io/crates/l/axum-keycloak-auth.svg)](#license)

Authenticate Axum requests with access tokens issued by Keycloak.

## Features

- Axum and Tower middleware for bearer-token authentication.
- Automatic OIDC discovery, with operational status for health reporting.
- Shared, rate-limited key refresh. Cached keys remain usable during Keycloak provider outages.
- Configurable validation for issuers, audiences, algorithms, token types, claims, and authorized parties.
- Blocking and passthrough modes for middleware-level or application-level error handling.
- Typed token claims, raw claims, realm roles, client roles, and application-defined role and claims types.
- Detailed programmatic errors, sanitized invalid-token responses, and opt-in diagnostic logging.

## Key refresh

Keys are refreshed on demand when no usable keys are cached or an unverifiable token names an unknown `kid`. There is
no periodic refresh. Reusing an existing `kid` for new key material does not by itself trigger a refresh, so publish
rotated keys under a new `kid`. Removed keys remain trusted until a refresh replaces the key set or the process
restarts.

## Installation

The default feature set uses `reqwest`'s default TLS backend:

```toml
[dependencies]
axum-keycloak-auth = "0.8.4"
```

To use rustls instead:

```toml
[dependencies]
axum-keycloak-auth = { version = "0.8.4", default-features = false, features = ["rustls-tls"] }
```

## Usage

`KeycloakAuthInstance` manages shared OIDC discovery and decoding keys. `KeycloakAuthLayer` extracts and validates a
token before calling protected handlers.

See the [API documentation](https://docs.rs/axum-keycloak-auth) for instance construction, strict validation, custom
claims, and token extraction.

```rust
use axum::{Extension, Router, routing::get};
use axum_keycloak_auth::{
    instance::KeycloakAuthInstance,
    layer::KeycloakAuthLayer,
    token::KeycloakToken,
};

pub fn protected_router(instance: KeycloakAuthInstance) -> Router {
    Router::new()
        .route("/protected", get(protected))
        .layer(
            KeycloakAuthLayer::<String>::builder()
                .instance(instance)
                .expected_audiences(vec![String::from("my-api")])
                .build(),
        )
}

pub async fn protected(Extension(token): Extension<KeycloakToken<String>>) -> String {
    format!("Authenticated subject: {}", token.subject)
}
```

### Authentication logging

Sensitive logging is disabled unless its layer setting is supplied. Each setting includes its own `tracing::Level`.
Applications using these settings should include `tracing = "0.1"` in their dependencies:

```rust
use axum_keycloak_auth::{
    instance::KeycloakAuthInstance,
    layer::{KeycloakAuthLayer, UnverifiedJwtHeaderLogging},
};
use tracing::Level;

fn logging_layer(instance: KeycloakAuthInstance) -> KeycloakAuthLayer<String> {
    KeycloakAuthLayer::<String>::builder()
        .instance(instance)
        .expected_audiences(vec![String::from("my-api")])
        .dangerously_log_authentication_errors(Level::WARN)
        .dangerously_log_token_extraction_errors(Level::DEBUG)
        .dangerously_log_unverified_jwt_header(UnverifiedJwtHeaderLogging::Metadata(Level::DEBUG))
        .build()
}
```

`dangerously_log_raw_claims(level)` logs the signature- and policy-validated claims map, which commonly contains
personal data. Typed-claim or role validation may still fail afterward. Never enable this setting in production.
`UnverifiedJwtHeaderLogging::Complete(level)` logs the complete attacker-controlled JWT header, while
`Metadata(level)` is limited to `alg`, `kid`, and `typ`. `dangerously_log_authentication_errors(level)` logs final
authentication failures. `dangerously_log_token_extraction_errors(level)` logs every extractor error and the
extractor's `Debug` output, including errors ignored during fallback. Custom extractor diagnostics may contain
credentials. Omitting a setting disables its event. Built-in diagnostics do not include bearer tokens.

## Axum compatibility

| axum-keycloak-auth | axum |
|--------------------|------|
| 0.2                | 0.6  |
| 0.3 - 0.6          | 0.7  |
| 0.7 - 0.8          | 0.8  |

## Development

### Tests

Run all tests, including the Podman-backed Keycloak integration tests:

```shell
just test
```

### Dependency security

Run the RustSec audit with:

```shell
just audit
```

### MSRV

The minimum supported Rust version is 1.89.

Raising the minimum supported Rust version is not treated as a breaking change and may happen in any release. This
policy applies from v0.8.4 onward.

Check the declared MSRV with:

```shell
just msrv
```

## License

This project is licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.
