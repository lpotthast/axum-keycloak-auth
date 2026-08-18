# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added CI checks for formatting, feature combinations, clippy, an SMRV check, RustSec auditing, unit and integration
  tests.
- Added new `just` recipes.
- Added CHANGELOG.md and backfilled old release information.

### Changed

- Raised the minimum supported Rust version from 1.85 to 1.89.
- Enabled pedantic Clippy lints and resolved all reported issues.
- Updated development dependencies.
- Integration-tests now use latest Keycloak 26.7.1.
- Migrated atomic-time: 0.1.5 → 0.2.1
- Migrated educe: 0.6.0 → 0.7.6

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

[Unreleased]: https://github.com/lpotthast/axum-keycloak-auth/compare/v0.8.3...HEAD
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
