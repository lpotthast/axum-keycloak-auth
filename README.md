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
- Background key refresh, plus shared, rate-limited refreshes for rotated keys. Configurable handling of keys that
  cannot be refreshed in time.
- Configurable validation for issuers, audiences, algorithms, token types, claims, and authorized parties.
- Blocking and passthrough modes for middleware-level or application-level error handling.
- Typed token claims, raw claims, realm roles, client roles, and application-defined role and claims types.
- Detailed programmatic errors, sanitized invalid-token responses, and opt-in diagnostic logging.

## Installation

Enable one of the crypto backend features, see [Crypto backend](#crypto-backend). Add `reqwest` as well, to build the
HTTP client the crate uses for OIDC discovery. It must be the same major version as the one this crate depends on
(0.13):

```toml
[dependencies]
axum-keycloak-auth = { version = "0.9.0", features = ["aws-lc-rs"] }
reqwest = "0.13"
```

This crate enables no `reqwest` TLS features itself. Choose the
[`reqwest` features](https://docs.rs/reqwest/0.13/reqwest/#optional-features) your application needs, in particular
the TLS backend. The defaults use rustls.

### Crypto backend

Token signatures are verified by `jsonwebtoken` 11, which needs a crypto backend. Select it with exactly one of these
features. Neither is enabled by default, and the crate does not compile without one.

- `aws-lc-rs` selects [aws-lc-rs](https://crates.io/crates/aws-lc-rs), which `reqwest`'s default rustls TLS backend
  uses as well. It builds C code, see its [build requirements](https://aws.github.io/aws-lc-rs/requirements/index.html).
- `rust-crypto` selects the pure-Rust [RustCrypto](https://github.com/RustCrypto) crates. `reqwest` can also be
  configured to use this backend.

`jsonwebtoken` picks its backend from its own `aws_lc_rs` and `rust_crypto` features, which every crate in your
dependency graph can enable. This crate never installs a provider itself. What you need to do depends on the feature
you enable:

- **`aws-lc-rs`:** Nothing else, as long as no other crate enables `jsonwebtoken`'s `rust_crypto` feature. If one does,
  install the aws-lc-rs provider before the first token is verified, for example at the start of `main`:

  ```rust
  axum_keycloak_auth::jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER
      .install_default()
      .expect("no other jsonwebtoken crypto provider must be installed yet");
  ```

- **`rust-crypto`:** Nothing else, as long as no other crate enables `jsonwebtoken`'s `aws_lc_rs` feature. If one does,
  install the RustCrypto provider before the first token is verified, for example at the start of `main`:

  ```rust
  axum_keycloak_auth::jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER
      .install_default()
      .expect("no other jsonwebtoken crypto provider must be installed yet");
  ```

Enabling both features of this crate also enables both backends, so it requires installing one of the providers above.
Without an installed provider, `jsonwebtoken` cannot choose between two enabled backends and panics on every token
verification, which first shows with an authenticated request, not at startup.
`cargo tree -e features -i jsonwebtoken` lists which crates enable which `jsonwebtoken` features.

To use a custom `jsonwebtoken::crypto::CryptoProvider`, still enable one of the features and install your provider
with `install_default` before the first token is verified. An installed provider takes precedence over the one the
features select. Whichever provider verifies, this crate only lets a decoding key verify tokens whose algorithm belongs
to the key's own algorithm family.

Install providers through the `axum_keycloak_auth::jsonwebtoken` re-export, or a direct dependency on the same
`jsonwebtoken` major version, because a provider installed into another version has no effect on this crate.

#### Not to be confused with rustls's `CryptoProvider`

rustls has a `CryptoProvider` with an `install_default` function as well, and both can be backed by aws-lc-rs, but the
two are unrelated. rustls's provider performs the cryptography of TLS connections, such as the HTTPS requests your
`reqwest::Client` makes for OIDC discovery. `jsonwebtoken`'s provider verifies token signatures. Each crate keeps its
own process-wide provider, and installing one never configures the other. The backend feature you choose for this crate
therefore does not change `reqwest`'s TLS cryptography either.

You may still need to install a rustls provider, independently of this crate. For example, `reqwest`'s
`rustls-no-provider` feature requires one before the first `Client` is built, and rustls cannot choose a default
provider by itself when more than one of its crypto backends is enabled. An application that needs both providers
installs each one, for example at the start of `main`:

```rust
// TLS, for reqwest and other rustls users. Requires a direct `rustls` dependency.
rustls::crypto::aws_lc_rs::default_provider()
    .install_default()
    .expect("no other rustls crypto provider must be installed yet");

// Token signatures. Only needed in the cases described above.
axum_keycloak_auth::jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER
    .install_default()
    .expect("no other jsonwebtoken crypto provider must be installed yet");
```

## Usage

`KeycloakAuthInstance` manages shared OIDC discovery and decoding keys. `KeycloakAuthLayer` extracts and validates a
token before calling protected handlers.

See the [API documentation](https://docs.rs/axum-keycloak-auth) for strict validation, custom claims, and token
extraction.

Create one instance per realm with your own `reqwest::Client`, which controls timeouts, proxies, and TLS:

```rust
use std::time::Duration;

use axum_keycloak_auth::instance::{KeycloakAuthInstance, KeycloakConfig, ServerUrl};

pub fn keycloak_instance() -> Result<KeycloakAuthInstance, Box<dyn std::error::Error>> {
    let config = KeycloakConfig::builder()
        .server(ServerUrl::parse("https://keycloak.example/")?)
        .realm(String::from("my-realm"))
        .build();
    let http_client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()?;
    let instance = KeycloakAuthInstance::builder()
        .config(config)
        .http_client(http_client)
        .build();
    Ok(instance)
}
```

Then protect routes with a layer using that instance:

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

### Readiness

The instance discovers Keycloak's keys in the background, and requests fail with `503 Service Unavailable` until it
succeeds. Report this through a readiness check outside the authentication layer, so that schedulers such as Kubernetes only
route traffic to the application once it can authenticate requests:

```rust
use std::sync::Arc;

use axum::{Router, extract::State, http::StatusCode, routing::get};
use axum_keycloak_auth::instance::KeycloakAuthInstance;

async fn ready(State(instance): State<Arc<KeycloakAuthInstance>>) -> StatusCode {
    if instance.operational_status().is_operational {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

pub fn readiness_router(instance: Arc<KeycloakAuthInstance>) -> Router {
    Router::new().route("/ready", get(ready)).with_state(instance)
}
```

The instance also stops being operational when its keys expired and are rejected, see [Key refresh](#key-refresh). A
Keycloak outage can therefore take every instance out of rotation within a few minutes, including routes that need no
authentication. If parts of the application must stay available without Keycloak, configure `ExpiredKeys::Trust` or a
longer `ExpiredKeys::TrustFor`. Use this check for readiness, not liveness: restarting the application does not make
Keycloak reachable.

Applications that must not run at all without Keycloak can instead await `KeycloakAuthInstance::wait_for_discovery` at
startup. This is an advanced option. Most applications should rely on the readiness check.

### Key refresh

A background task refreshes Keycloak's keys every four minutes by default, independently of request traffic, so that
requests never wait for routine refreshes. It also keeps retrying a failed initial discovery. Tokens naming an unknown
`kid` additionally trigger a shared, rate-limited refresh, so newly rotated keys are picked up right away. Changed key
material under an existing `kid` is only picked up by the next refresh, at the latest the periodic one, so publish
rotated keys under a new `kid`.

Keys older than the maximum key age, five minutes by default, only occur while refreshes fail, for example because
Keycloak is unreachable. What happens with them is configurable with `ExpiredKeys`:

- `TrustFor(duration)`, the default with one minute: expired keys are used for that much longer, then rejected.
  Keys therefore stop verifying tokens at most six minutes after the last successful refresh.
- `Reject`: expired keys are rejected right away.
- `Trust`: expired keys are used until a refresh succeeds. This keeps the application available during a Keycloak
  outage of any length, but a key removed from Keycloak, for example because it was compromised, then keeps verifying
  tokens for as long as the instance cannot reach Keycloak.

While keys are rejected, requests fail with `503 Service Unavailable`, and the instance reports itself as not
operational, which takes it out of rotation through the readiness check. The first successful refresh makes it
operational again.

Key ages are measured on both the monotonic and the wall clock, so time the system spent suspended counts as well. A
single discovery, including its retries, is abandoned after one minute by default, so a Keycloak that stops answering
cannot block later refreshes. Create the instance on the runtime that serves requests: its background task belongs to
the runtime that created it.

Configure these settings with a `DiscoveryConfig`:

```rust
use std::time::Duration;

use axum_keycloak_auth::instance::{
    DiscoveryConfig, ExpiredKeys, KeycloakAuthInstance, KeycloakConfig, ServerUrl,
};

pub fn keycloak_instance() -> Result<KeycloakAuthInstance, Box<dyn std::error::Error>> {
    let config = KeycloakConfig::builder()
        .server(ServerUrl::parse("https://keycloak.example/")?)
        .realm(String::from("my-realm"))
        .build();
    let http_client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()?;
    let discovery_config = DiscoveryConfig::builder()
        .refresh_after(Duration::from_secs(240))
        .max_key_age(Duration::from_secs(300))
        .expired_keys(ExpiredKeys::Reject)
        .build()?;
    let instance = KeycloakAuthInstance::builder()
        .config(config)
        .http_client(http_client)
        .discovery_config(discovery_config)
        .build();
    Ok(instance)
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
