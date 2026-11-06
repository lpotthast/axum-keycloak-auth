# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0] - Unreleased

### Security

- **Breaking:** A background task owned by `KeycloakAuthInstance` now refreshes the decoding keys every four minutes by
  default, independently of request traffic. Keys that could not be refreshed for longer than a maximum key age, five
  minutes by default, expire, and expired keys are rejected one minute later. In 0.8.4, keys were never refreshed
  periodically, so a key removed from Keycloak, for example because it was compromised, kept verifying tokens until a
  token with an unknown `kid` triggered a refresh or the process restarted, and no such token arrives while all
  legitimate tokens name a cached key. Such a key now stops verifying tokens at most six minutes after the last
  successful refresh. Changed key material under an existing `kid` is picked up by the same refreshes. Key ages count
  time the system spent suspended, and a discovery that does not finish within one minute, including its retries, is
  abandoned and counts as failed, so that a Keycloak that stops answering cannot block later refreshes. While keys are
  rejected, requests fail with the new `AuthError::DecodingKeysExpired`, answered with `503 Service Unavailable`, and
  `KeycloakAuthInstance::is_operational` and `OperationalStatus::is_operational` report `false`, so a Keycloak outage
  now takes instances out of rotation after two to six minutes, depending on how long before the outage their keys
  were last refreshed. The new `ExpiredKeys` setting can instead keep using expired keys until a refresh succeeds, as
  0.8.4 did, or reject them right away. Instances now request the discovery document and JWKS every four minutes,
  also while idle.

### Added

- Added `instance::DiscoveryConfig`, created with `DiscoveryConfig::builder()` and passed to the new
  `KeycloakAuthInstanceBuilder::discovery_config` setting. It configures the request retries and retry delay of each
  discovery, how long one discovery may take, the age at which keys are refreshed in the background, the maximum key
  age, what happens with expired keys through the new `ExpiredKeys`, and how long requests wait for a shared refresh,
  which was fixed at five seconds before. Requests no longer wait for a refresh that started longer ago than that. Its
  `DEFAULT_*` constants and `ExpiredKeys::DEFAULT` document the defaults. Its builder's `build` returns the new
  `DiscoveryConfigError` if the refresh age is not below the maximum key age, if the maximum key age is below
  `DiscoveryConfig::MIN_MAX_KEY_AGE` (ten seconds), or if the discovery timeout is zero.
- Added `AuthError::DiscoveryTimedOut`, which `KeycloakAuthInstance::wait_for_discovery` returns when the initial
  discovery did not finish within the discovery timeout. `wait_for_discovery` therefore no longer waits longer than that
  timeout, one minute by default, and returns the new `AuthError::DecodingKeysExpired` when the discovered keys are
  rejected.
- Re-exported `reqwest`, the HTTP client library whose `Client` `KeycloakAuthInstance::builder` requires.
- Re-exported `jsonwebtoken`, the JWT library this crate verifies tokens with, so that an application installing a
  `jsonwebtoken::crypto::CryptoProvider` installs it into the same `jsonwebtoken` version this crate uses.

### Changed

- **Breaking:** `AuthError::NoDecodingKeys`, returned while no discovery yielded usable keys yet, is now answered with
  `503 Service Unavailable` and the body `{"error":"Authentication is temporarily unavailable."}`, without a
  `WWW-Authenticate` challenge, instead of `401 Unauthorized` with the error's description, because the server cannot
  verify any token, however valid it is. The new `AuthError::DecodingKeysExpired` gets the same response.
- **Breaking:** `KeycloakAuthInstance::builder` no longer takes the `KeycloakConfig` as an argument and now requires the
  `reqwest::Client` used for OIDC discovery and key refreshes. Both are set through the builder, as in
  `KeycloakAuthInstance::builder().config(config).http_client(http_client).build()`, which does not compile until both
  are set. The crate no longer creates a default client, so timeouts, proxies, and the TLS backend are entirely the
  application's choice.
- **Breaking:** Updated `jsonwebtoken` from 9 to 11. `validation::Algorithm`, which this crate re-exports from it, is
  now `#[non_exhaustive]`, and the `source` of `AuthError::Decode` and `AuthError::DecodeHeader` is now a
  `jsonwebtoken` 11 error.
- **Breaking:** The crate now requires one of the new `aws-lc-rs` and `rust-crypto` features, which select the crypto
  backend `jsonwebtoken` verifies token signatures with. Neither is enabled by default, and the crate does not compile
  without one, so enable one, for example with `features = ["aws-lc-rs"]`. The crate never installs a
  `jsonwebtoken::crypto::CryptoProvider` itself. If both `jsonwebtoken` backends end up enabled, through feature
  unification, the application must install one crypto provider at startup explicitly. Otherwise `jsonwebtoken`
  panics on every token verification, which first shows with an authenticated request, not at startup. The README
  section "Crypto backend" describes what each feature requires. Whichever provider verifies, this crate only lets a
  decoding key verify tokens whose algorithm belongs to the key's own algorithm family.
- **Breaking:** `KeycloakConfig::server` is now a `ServerUrl`, created with `ServerUrl::parse("https://...")`, through
  `FromStr`, or from a parsed `Url` with `ServerUrl::new(url)`. A URL that cannot serve as a base URL is rejected there
  with an `InvalidServerUrlError`, so `KeycloakAuthInstanceBuilder::build` no longer returns a `Result`, and
  `KeycloakConfig::issuer` no longer panics on such a URL.
- **Breaking:** `InvalidServerUrlError` is now a non-exhaustive enum. `CannotBeABase { url }` replaces the former
  struct and its `url()` accessor, and `Parse { input, source }` reports input that is not a valid URL.
- **Breaking:** `KeycloakAuthInstance::is_operational` is no longer `async`. Remove the `.await` from its calls.
- **Breaking:** Marked `AuthError` and `RequestError` as `#[non_exhaustive]`, so future releases can add variants
  without a breaking change. Exhaustive `match` expressions on them need a wildcard arm.
- **Breaking:** `TokenExtractor::extract` now returns `Result<Option<ExtractedToken>, extract::BoxError>`. An extractor
  reports an absent credential source as `Ok(None)`, and a present but unusable one as an error of any type, which `?`
  converts. A custom extractor that still returns an error such as `AuthError::MissingToken` for an absent source
  therefore reports a present source and causes every request to be rejected.
  `dangerously_log_token_extraction_errors` no longer logs absent sources.
- **Breaking:** Every configured token extractor is now asked, and a request with credentials in more than one source
  is rejected with the new `AuthError::MultipleCredentialSources`, answered with `400 Bad Request` and a
  `WWW-Authenticate: Bearer error="invalid_request"` challenge, because RFC 6750 forbids clients to send a token by
  more than one method. This applies even if the sources carry the same valid token, and to a malformed higher-priority
  source, such as a blank `Authorization: Bearer` header next to a valid query token, which 0.8.4 authenticated with
  the query token by default.
- **Breaking:** A sole credential source that is present but unusable now fails authentication with
  `AuthError::TokenExtraction`, whose source is the extractor's error, such as the new public `AuthHeaderExtractError`
  and `QueryParamExtractError` of the built-in extractors. 0.8.4 reported `AuthError::MissingToken` by default, and an
  extraction-specific `AuthError` variant under `TokenExtractionErrorPolicy::Reject`. The response is still
  `401 Unauthorized` with a `WWW-Authenticate: Bearer` challenge, but its body is now the generic
  `{"error":"The request carried an unusable credential."}`, and a query token that is not valid UTF-8 no longer gets
  the `invalid_token` challenge. `dangerously_log_authentication_errors` logs the extractor's error as the `source`
  field.
- `AuthHeaderTokenExtractor` now matches the `Bearer` scheme case-insensitively, as RFC 7235 requires, and treats an
  `Authorization` header with another scheme, such as `Basic`, as an absent credential source instead of an unusable
  one. Such a header therefore neither fails authentication nor counts as a second credential source.
- The `discovery_kind` field of the `perform_oidc_discovery` tracing span now names what caused a discovery: `Initial`,
  `Scheduled` for the new background refreshes, or, for discoveries that requests caused, `Overdue`, `NoKeys`,
  `UnknownKid`, or `KeysExpired`. 0.8.4 reported every discovery after the initial one as `OnDemand`.

Dependency changes:

- **Breaking:** Updated `reqwest` from 0.12 to 0.13. The `reqwest::Client` passed to `KeycloakAuthInstance::builder`
  must now be built with `reqwest` 0.13, so update your application's own `reqwest` dependency too. Its default TLS
  backend is now rustls instead of native TLS, and its `rustls-tls` feature is now called `rustls`. Enable `reqwest`'s
  `native-tls` feature to keep native TLS.
- **Breaking:** Updated `nonempty` from 0.11 to 0.12. The re-exported `NonEmpty`, which `KeycloakAuthLayer`'s
  `token_extractors` takes, is now the 0.12 type. Build the extractors with `axum_keycloak_auth::NonEmpty` or with
  `nonempty` 0.12.

### Fixed

- An instance whose initial discovery failed now becomes operational once Keycloak is reachable, without needing
  requests. In 0.8.4, only requests retried the discovery, so behind the documented readiness check, which keeps traffic
  away from an instance that is not operational, the instance never recovered.

### Removed

- **Breaking:** Removed `KeycloakConfig::retry`. Configure retries with `DiscoveryConfigBuilder::request_retries` and
  `DiscoveryConfigBuilder::request_retry_delay`, which takes a `Duration` instead of whole seconds. Previous defaults
  are unchanged.
- **Breaking:** Removed the `decode` module, deprecated since 0.8.4. Import its types from `token` instead, for example
  `axum_keycloak_auth::token::KeycloakToken`.
- **Breaking:** Removed the `oidc_discovery` module. Import `RequestError` from `error` instead.
- **Breaking:** Removed the `AuthError::NoJwkSetDiscovery` and `AuthError::CreateDecodingKey` variants, which were no
  longer returned. A discovery that yields no usable keys is reported as `AuthError::NoDecodingKeys`.
- **Breaking:** Made the `oidc` module, which contained the OIDC discovery-document models, private. No public API used
  them.
- **Breaking:** Removed `KeycloakAuthInstance::new`. Use `KeycloakAuthInstance::builder` instead.
- **Breaking:** Removed the `default-tls` and `rustls-tls` features and the default features, which only configured
  `reqwest` for the removed default client. Select `reqwest` features, such as the TLS backend, through the
  application's own `reqwest` dependency.
- **Breaking:** Removed `TokenExtractionErrorPolicy` and the `KeycloakAuthLayer` `token_extraction_error_policy`
  setting, which are meaningless now that credentials in more than one source are rejected. For now, there is no
  opt-out for clients that send several tokens.
- **Breaking:** Removed the `AuthError` variants `MissingAuthorizationHeader`, `MissingQueryParams`,
  `MissingTokenQueryParam`, `InvalidAuthorizationHeader`, `MissingBearerToken`, and `EmptyTokenQueryParam`. Absent
  credential sources are now reported by extractors as `Ok(None)`, and unusable ones as `AuthError::TokenExtraction`.
  `AuthError::MissingToken` still reports that no extractor was able to ultimately find a token.

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

[Unreleased]: https://github.com/lpotthast/axum-keycloak-auth/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/lpotthast/axum-keycloak-auth/compare/v0.8.4...v0.9.0
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
