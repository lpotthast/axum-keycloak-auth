# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.4] - 2026-10-19

### Security

- Bearer tokens that fail decoding or validation now consistently return `401 Unauthorized` with the generic body
  `{"error":"invalid_token"}` and a `WWW-Authenticate: Bearer error="invalid_token"` challenge. Undecodable token
  headers previously returned `400 Bad Request`. Detailed errors remain available through `AuthError` and the optional
  `dangerously_log_authentication_errors(level)` setting, but are no longer exposed to clients or logged by default.
  The separate `dangerously_log_token_extraction_errors(level)` setting logs every token extractor error and the
  extractor's `Debug` output when explicitly enabled. Typed claim parsing failures previously returned `500 Internal
  Server Error`, exposing internal details, while fallback extraction errors previously bypassed the logging opt-in.
- Missing-role `403 Forbidden` responses no longer expose the exact required role in debug builds and now use the same
  generic response in every build profile. The role remains available as a structured log field when the explicit
  `dangerously_log_authentication_errors(level)` setting is enabled.
- Unverified JWT headers are no longer logged in full by default. The optional
  `dangerously_log_unverified_jwt_header` setting combines content and severity: omitting it disables the event,
  `UnverifiedJwtHeaderLogging::Metadata(level)` logs only `alg`, `kid`, and `typ`, and
  `UnverifiedJwtHeaderLogging::Complete(level)` explicitly opts into the full attacker-controlled header.
- Added regression coverage ensuring a token cannot use its header to select an incompatible verification algorithm,
  such as treating asymmetric key material as an HMAC secret. Released versions were not affected.
- Symmetric (`kty: oct`) JWKs and JWKs published for encryption (`use: enc`) are no longer used to verify token
  signatures. A symmetric key in a published JWKS would let anyone who can read it forge tokens.

### Fixed

- Tokens signed with newly rotated provider keys are now accepted after one shared JWKS refresh. Previously, an unknown
  `kid` could cause every new token to be rejected until the service restarted. If a refreshed key verifies the
  signature but claim validation fails, direct and passthrough diagnostics now report the claim failure instead of the
  cached key's `InvalidSignature`.
- OIDC discovery failures, panics, and cancellations no longer leave concurrent requests hanging. Dropping the last
  instance owner now aborts in-flight provider discovery instead of retaining its HTTP client and connection, while a
  shared refresh still survives cancellation of an individual validation waiter. Attempting an on-demand refresh
  outside a Tokio runtime now panics promptly instead of deadlocking. The last successfully retrieved keys remain
  available until a later refresh succeeds.
- Malformed `exp` and `iat` claims, and malformed `nbf` claims when `nbf` validation is enabled, now fail closed. In
  particular, a non-integer `exp` returns `401 Unauthorized` instead of `500 Internal Server Error`.
- Query-parameter tokens containing invalid UTF-8 now return `401 Unauthorized` instead of panicking.
- Empty or whitespace-only credentials no longer block lower-priority token extractors. `Authorization: Bearer ` now
  yields `MissingBearerToken`, while `?token=` yields `EmptyTokenQueryParam`.
- `Profile::full_name` now falls back to Keycloak's standard `name` claim when no `full_name` claim is present. Tokens
  carrying both claims remain accepted and keep reading `full_name`.
- The `expect_role!`, `expect_roles!`, `not_expect_role!`, and `not_expect_roles!` macros now work when the crate is
  renamed in `Cargo.toml` and no longer require `axum` as a direct dependency of the calling crate.
- Server URLs with a trailing slash after a non-root path, such as `https://host/auth/`, now produce the correct OIDC
  discovery URL without a duplicate slash.

### Added

- Added the public `validation` module and `ValidationPolicy`. `ValidationPolicy::legacy()` preserves existing behavior,
  while the opt-in `ValidationPolicy::strict()` enforces named issuers, matching audiences, asymmetric algorithms,
  access-token types, and consistent `exp`, `nbf`, and `iat` checks. Policies support required claims, clock skew,
  expiry transit margins, and `azp` constraints, and return typed `ValidationPolicyError`s for invalid configurations.
- Added `KeycloakAuthInstance::connect` and `connect_with_client` to await initial OIDC discovery and fail fast with
  `ConnectError`. `connect_with_client` accepts a caller-supplied `reqwest::Client` for custom timeouts, proxies, trust
  roots, and mTLS.
- Added `KeycloakAuthInstance::ready` and `operational_status`, returning the new `OperationalStatus` type, for startup
  coordination and health reporting.
- Added `TokenExtractionErrorPolicy` to control whether malformed credentials fall through to lower-priority extractors
  (`Fallback`, the default) or fail closed (`Reject`).
- Added the `token` module as the new home for token and claim types. The deprecated `decode` module remains as a
  compatibility alias until the next breaking release. Rust reports the deprecation only where the module itself is
  imported, not for paths such as `decode::KeycloakToken`, so migrate those paths proactively.
- Added `dangerously_log_raw_claims(level)` for explicitly logging complete signature- and policy-validated raw JWT
  claims, including personal data, at a chosen severity. Omitting it disables the event. Typed-claim or role validation
  may still reject a request after the claims are logged, and this setting must not be enabled in production.

### Changed

- Raised the minimum supported Rust version from 1.85 to 1.89. Starting with this release, an MSRV increase is no longer
  considered a breaking change, matching common practice in the Rust ecosystem.
- Provider requests now share a connection-pooled HTTP client with default connect and request timeouts of 10 and 30
  seconds. Non-success HTTP responses are now reported as request errors, and retried like them, instead of being
  decoded as JSON.
- On-demand OIDC discovery and JWKS refreshes for unverifiable tokens with unknown key IDs are now single-flight,
  rate-limited after success, and retried with exponential backoff after failure. Requests wait at most five seconds
  for a shared refresh, including initial discovery. The `KeycloakConfig::retry` attempts still apply within each
  refresh. Refreshes remain on demand, so removed keys stay trusted until another refresh or restart.
- `KeycloakAuthService::poll_ready` no longer waits for initial discovery. Requests that need decoding keys wait inside
  the service call instead, bounded by the five-second refresh wait.
- `KeycloakAuthInstance::is_operational` now reports whether at least one usable decoding key is cached. A discovery
  without usable keys is no longer operational, and a failed refresh no longer clears the operational state while the
  previous keys remain usable.
- `401 Unauthorized` responses for missing or unusable credentials now carry a `WWW-Authenticate: Bearer` challenge.
- Claims validation now runs once after signature verification, preserving meaningful expiry, audience, and malformed
  token errors regardless of cached-key order. Tokens already verified by a cached key no longer trigger a pointless
  refresh solely because their `kid` is unknown.
- Signature failures now prefer errors from keys in the token's algorithm family, making diagnostics independent of
  provider key order.
- Revised the public API documentation for accuracy and consistency, added coverage for previously undocumented items,
  and enabled the missing-documentation lint outside the standards-derived OIDC metadata models.
- Removed the `atomic-time` and `educe` dependencies.
- Expanded CI and `just` automation for formatting, feature combinations, Clippy, MSRV, RustSec, unit tests, and
  integration tests, and enabled pedantic Clippy lints.
- Updated development dependencies, including `assertr` 0.9.1, and integration tests to Keycloak 26.7.2.
- Added the changelog and backfilled earlier releases.

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
