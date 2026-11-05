# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed

- **Breaking:** Removed the `decode` module, deprecated since 0.8.4. Import its types from `token` instead, for example
  `axum_keycloak_auth::token::KeycloakToken`.
- **Breaking:** Removed the `oidc_discovery` module. Import `RequestError` from `error` instead.
- **Breaking:** Removed the `AuthError::NoJwkSetDiscovery` and `AuthError::CreateDecodingKey` variants, which were no
  longer returned. A discovery that yields no usable keys is reported as `AuthError::NoDecodingKeys`.

## [0.8.4] - 2026-11-05

### Security

- Bearer tokens that fail decoding or validation now return `401 Unauthorized` with the generic body
  `{"error":"invalid_token"}` and a `WWW-Authenticate: Bearer error="invalid_token"` challenge. Previously, undecodable
  token headers returned `400 Bad Request`, typed claim parsing failures returned `500 Internal Server Error`. These
  responses included detailed error text. Detailed errors remain available through `AuthError`, for example with
  `PassthroughMode::Pass` or from `KeycloakAuthLayer::validate_raw_token`. The middleware only logs them when the new
  `dangerously_log_authentication_errors(level)` setting is enabled.
- Missing-role `403 Forbidden` responses, including those produced by the role macros, no longer expose the required
  role in debug builds and now use the same generic body in every build profile. The role remains available in
  `AuthError::MissingExpectedRole`. For the layer's `required_roles`, it is also logged as the structured `missing_role`
  field when `dangerously_log_authentication_errors(level)` is enabled.
- Decoded JWT claims, which commonly contain personal data, are no longer logged at `DEBUG` level for every validated
  token. The new `dangerously_log_raw_claims(level)` setting explicitly opts into that old behavior. It logs the claims
  once signature and policy validation succeeded, before typed-claim and role checks, so the claims of a token that
  ultimately fails authentication may still be logged. It must not be enabled in production.
- Token extractor errors, together with the extractor's `Debug` output, are no longer logged at `DEBUG` level. The new
  `dangerously_log_token_extraction_errors(level)` setting explicitly opts into that old behavior.
- Unverified JWT headers are no longer logged in full at `DEBUG` level. The optional
  `dangerously_log_unverified_jwt_header` setting combines content and severity: omitting it disables the event,
  `UnverifiedJwtHeaderLogging::Metadata(level)` logs only `alg`, `kid`, and `typ`, and
  `UnverifiedJwtHeaderLogging::Complete(level)` explicitly opts into logging the full potentially attacker-controlled
  header.
- Symmetric (`kty: oct`) JWKs and JWKs published for encryption (`use: enc`) are no longer used to verify token
  signatures. A symmetric key in a published JWKS would let anyone who can read it forge tokens. As in earlier
  releases, a token cannot use its header to select an algorithm incompatible with the key, such as treating asymmetric
  key material as an HMAC secret.

### Fixed

- Tokens signed with a newly rotated provider key are now accepted. A token whose `kid` matches no cached key triggers
  a shared, rate-limited re-discovery of the provider's keys. Previously, keys were only re-fetched while none were
  cached, so tokens signed with a new key were rejected until the service restarted.
- A panicking or cancelled OIDC discovery, for example one dropped by a shutting-down Tokio runtime, no longer leaves
  requests waiting for it hanging forever. Races between checking for an in-flight discovery and waiting for its
  completion, which could also leave requests hanging, are fixed. Dropping the last instance owner now aborts an
  in-flight discovery instead of letting it run on in the background.
- `KeycloakAuthService::poll_ready` no longer panics on a failed assertion when it runs before the initial discovery
  task has started, for example on a current-thread runtime.
- Tokens with a fractional or out-of-range numeric `exp` claim, or a malformed `iat` claim, are now rejected with
  `401 Unauthorized` instead of causing a `500 Internal Server Error`.
- Query-parameter tokens containing invalid UTF-8 are now treated as unusable credentials instead of causing a panic.
- Whitespace around Authorization-header and query-parameter tokens is now ignored, so several spaces after the
  `Bearer ` scheme are accepted as RFC 6750 permits. An empty or whitespace-only query-parameter token, such as
  `?token=`, now yields `EmptyTokenQueryParam` and no longer stops lower-priority token extractors. Previously, it was
  extracted as an empty token and rejected with `400 Bad Request`.
- `Profile::full_name` now falls back to Keycloak's standard `name` claim when no `full_name` claim is present.
- The `expect_role!`, `expect_roles!`, `not_expect_role!`, and `not_expect_roles!` macros now work when the crate is
  renamed in `Cargo.toml` and no longer require `axum` as a direct dependency of the calling crate.
- Server URLs with a trailing slash after a non-root path, such as `https://host/auth/`, now produce the correct OIDC
  discovery URL without a duplicate slash.

### Added

- Added the `validation` module with `ValidationPolicy` and `ValidationPolicyBuilder`, configured through the new
  `KeycloakAuthLayer` `validation_policy` setting. The default `ValidationPolicy::legacy()` keeps the validation of
  earlier releases. The opt-in `ValidationPolicy::strict()` requires named issuers, a matching audience, an asymmetric
  signature algorithm, and the `Bearer` token type, and additionally validates `nbf` and `iat`. It applies one
  clock-skew leeway to `exp`, `nbf`, and `iat` alike, so unlike `legacy()` it accepts a token until its `exp` lies more
  than the leeway in the past. Policies support required claims, clock skew, expiry transit margins, and `azp`
  allowlists, and their `build` returns a typed `ValidationPolicyError` for invalid configurations. List settings accept
  any iterable, such as `.expected_audiences(["my-api"])`.
- Added `KeycloakConfig::issuer`, which derives a realm's token issuer (`<server>/realms/<realm>`) for
  `ValidationPolicyBuilder::expected_issuers`, handling a trailing slash on the server URL like OIDC discovery does.
- Added `KeycloakAuthInstance::wait_for_discovery`, which waits for initial OIDC discovery and returns its error, for
  applications that must not run without Keycloak. Most applications should report readiness through
  `operational_status` instead.
- Added `KeycloakAuthInstance::builder` to supply a custom `reqwest::Client` through `http_client` for timeouts,
  proxies, trust roots, and mTLS. Its `build` reports an unusable server URL as an `InvalidServerUrlError` naming the
  rejected URL. Supplying a client is now the documented way to create an instance, and a future release will require
  it.
- Added `KeycloakAuthInstance::operational_status`, returning the new `OperationalStatus` type with the latest
  `DiscoveryFailure`, for readiness and health reporting.
- Added `TokenExtractionErrorPolicy`, configured through the new `KeycloakAuthLayer` `token_extraction_error_policy`
  setting, to control whether a present but malformed credential falls through to lower-priority extractors
  (`Fallback`, the default and previous behavior) or fails authentication (`Reject`).
- Added the `token` module as the new home for token and claim types.

### Changed

- Raised the minimum supported Rust version from 1.85 to 1.89. Starting with this release, an MSRV increase is no longer
  considered a breaking change, matching common practice in the Rust ecosystem.
- Provider requests now reuse one connection-pooled HTTP client per instance instead of creating a client per request.
  The default client has connect and request timeouts of 10 and 30 seconds, where requests previously had none.
  Non-success HTTP responses are now reported as `RequestError::Send` instead of being decoded as JSON.
- OIDC discovery and JWKS refreshes run on demand when no usable decoding keys are cached or when a token with an
  unknown key ID fails verification. They are now single-flight, wait about five seconds after a success before
  refreshing again, and back off exponentially from one second up to one minute after failures, with
  `KeycloakConfig::retry` still applying within each refresh. Requests wait at most five seconds for a shared refresh,
  including initial discovery. A refresh that yields no usable keys keeps the previous keys, so keys removed by the
  provider stay trusted until a refresh returns at least one usable key, or until restart.
- `KeycloakAuthService::poll_ready` no longer waits for initial discovery. Requests that need decoding keys wait inside
  the service call instead, bounded by the five-second refresh wait.
- `KeycloakAuthInstance::is_operational` now reports whether at least one usable decoding key is cached. A discovery
  without usable keys is no longer operational, and a failed refresh no longer clears the operational state while the
  previous keys remain usable.
- `401 Unauthorized` responses for missing or unusable credentials, and for missing decoding keys, now carry a
  `WWW-Authenticate: Bearer` challenge.
- Validation errors no longer depend on the order of the provider's keys: claim failures such as expiry or audience
  mismatches are reported reliably, and signature failures prefer keys in the token's algorithm family.
- Failed OIDC refreshes and undecodable JWKs are now logged at `WARN` instead of `ERROR`.
- Documented the entire public API.
- Removed the `atomic-time` and `educe` dependencies.

### Deprecated

- Deprecated the `decode` module in favor of `token`. It remains as a compatibility alias until the next breaking
  release.

## [0.8.3] - 2025-05-18

### Changed

- Updated `typed-builder` to 0.21.
- Updated development dependencies and the integration-test environment to Keycloak 26.2.4.

## [0.8.2] - 2025-03-25

### Changed

- Updated the documentation and integration coverage for merging routers that use different middleware modes.

## [0.8.1] - 2025-03-02

### Changed

- Updated `try-again` to 0.2 and refreshed transitive dependencies.

## [0.8.0] - 2025-02-20

### Changed

- **Breaking:** Raised the minimum supported Rust version from 1.74.1 to 1.85.
- Migrated the crate to Rust 2024 edition.

## [0.7.1] - 2025-02-20

### Changed

- Updated `serde-querystring` to 0.3 and refreshed other dependencies.

## [0.7.0] - 2025-01-05

### Changed

- **Breaking:** Updated `axum` to 0.8.
- **Breaking:** Updated `nonempty` to 0.11.
- Updated the remaining dependencies.

## [0.6.0] - 2024-09-12

### Added

- Added a configurable retry strategy for OIDC discovery.
- Added `default-tls` and `rustls-tls` features for choosing the `reqwest` TLS implementation.
- Added `KeycloakAuthLayer::validate_raw_token` for token validation outside the Axum middleware.
- Added configurable token extractors, including extraction from query parameters.

### Changed

- Authentication failures now distinguish bad requests, unauthorized tokens, forbidden roles, and internal discovery
  errors through their HTTP response status codes.
- OIDC discovery is retried only when token validation indicates that server keys may be stale, avoiding unnecessary
  requests to Keycloak.
- Updated `reqwest` to 0.12, `tower` to 0.5, and `typed-builder` to 0.20, among other dependency updates.

### Fixed

- Fixed middleware readiness handling that could cause requests to time out.

## [0.5.0] - 2024-02-02

### Added

- Added a generic, flattened `Extra` claims type across the token and middleware APIs, allowing applications to
  deserialize custom token claims.
- Added `ProfileAndEmail` as the default extra claims type.

### Changed

- **Breaking:** Moved the formerly required profile and email fields under `KeycloakToken::extra` and made the
  appropriate profile fields optional.

## [0.4.1] - 2024-01-30

### Fixed

- Fixed a deadlock when an undecodable JWT triggered OIDC discovery while discovery was already running.

## [0.4.0] - 2024-01-25

### Added

- Added automatic OIDC discovery, including automatic retries after JWT decoding failures.
- Added `KeycloakAuthInstance` for sharing discovered configuration and decoding keys across layers and checking
  operational health.
- Added support for JWT `aud` claims encoded as a list of audiences.

### Changed

- **Breaking:** Decoding keys are now discovered automatically and can no longer be supplied manually.
- **Breaking:** Moved `KeycloakAuthLayer` from the `service` module to the new `layer` module and reorganized the
  middleware service API.
- **Breaking:** Changed `KeycloakToken::audience` from a single string to a list of strings.
- **Breaking:** Raised the minimum supported Rust version from 1.67.1 to 1.74.1.
- Updated `snafu` to 0.8.

## [0.3.0] - 2023-12-21

### Changed

- **Breaking:** Updated `axum` from 0.6 to 0.7 and `http` from 0.2 to 1.0.

## [0.2.0] - 2023-10-20

### Added

- Added required `expected_audiences` configuration and validation of the JWT `aud` claim.

### Changed

- **Breaking:** `KeycloakAuthLayer` builders must now specify accepted audience values.
- **Breaking:** Raised the minimum supported Rust version from 1.56 to 1.67.1.
- Updated `jsonwebtoken` from 8 to 9 and `typed-builder` from 0.14 to 0.18.

## [0.1.2] - 2023-03-16

### Added

- Added optional layer-wide `required_roles` validation.

### Changed

- Updated `typed-builder` from 0.12 to 0.14.

## [0.1.1] - 2023-02-27

### Removed

- Removed the obsolete `once_cell` dependency.

## [0.1.0] - 2023-02-27

### Added

- Initial release.

[Unreleased]: https://github.com/lpotthast/axum-keycloak-auth/compare/v0.8.4...HEAD
[0.8.4]: https://github.com/lpotthast/axum-keycloak-auth/compare/v0.8.3...v0.8.4
[0.8.3]: https://github.com/lpotthast/axum-keycloak-auth/compare/v0.8.2...v0.8.3
[0.8.2]: https://github.com/lpotthast/axum-keycloak-auth/compare/v0.8.1...v0.8.2
[0.8.1]: https://github.com/lpotthast/axum-keycloak-auth/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/lpotthast/axum-keycloak-auth/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/lpotthast/axum-keycloak-auth/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/lpotthast/axum-keycloak-auth/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/lpotthast/axum-keycloak-auth/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/lpotthast/axum-keycloak-auth/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/lpotthast/axum-keycloak-auth/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/lpotthast/axum-keycloak-auth/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/lpotthast/axum-keycloak-auth/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/lpotthast/axum-keycloak-auth/compare/3421759...v0.2.0
[0.1.2]: https://github.com/lpotthast/axum-keycloak-auth/compare/v0.1.1...3421759
[0.1.1]: https://github.com/lpotthast/axum-keycloak-auth/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/lpotthast/axum-keycloak-auth/releases/tag/v0.1.0
