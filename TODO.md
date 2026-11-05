# TODO

## Next breaking release

### Accept `impl Into` inputs in the public builders

The `KeycloakConfig` and `KeycloakAuthLayer` builders take owned types, so callers write
`.realm(String::from("my-realm"))` and `.expected_audiences(vec![String::from("my-api")])`.
Widening these setters breaks existing callers, because the compiler can no longer infer the
target type of their arguments:

- `KeycloakConfig::realm`: use `#[builder(setter(into))]` to allow `.realm("my-realm")`. This
  breaks `.realm(x.into())`.
- `KeycloakAuthLayer::expected_audiences`: accept any iterable of `impl Into<String>`, like
  `ValidationPolicyBuilder::expected_audiences`, to allow `.expected_audiences(["my-api"])`. This
  breaks `vec![]`, `Vec::new()`, and `x.into()`. Passing an empty vector is what the field's
  documentation currently recommends when the validation policy defines its own audiences, so
  that advice must change with it.

### Reject inconsistent layer configuration when building the layer

A validation policy that requires an audience while none is configured rejects every token, but
it is only logged as a warning when the first service or validator is created (see `validator()`
in `layer.rs`). Make building a `KeycloakAuthLayer` fallible and return this as an error.

### Remove `ValidationPolicy::legacy()`

`legacy()` is the default preset and only exists to keep the acceptance rules of releases before 0.8.4. It does not
restrict `iss`, payload `typ`, or algorithms, accepts a missing `aud`, and skips `nbf` and future `iat` checks. Remove
it and make `strict()` the only preset and the default. This needs:

- A default issuer. `strict()` fails to build without `expected_issuers`, so `ValidationPolicy::default()` cannot be
  strict on its own. Derive the issuer from the layer's instance through `KeycloakConfig::issuer` when the policy does
  not name one, similar to how the policy inherits the layer's `expected_audiences` today.
- A decision on audiences. `strict()` requires a matching `aud`, so a layer without expected audiences would reject
  every token. Settle this together with the layer's `expected_audiences`, which may be removed in favor of the
  policy's, and with making layer building fallible.
- Removing `ExpirySemantics::LegacySecondCheck` and the second expiry check without leeway that it selects, so that
  `exp` uses the policy's leeway like `nbf` and `iat`.
- Updating the presets' documentation, the crate-level validation docs, and the `legacy_policy` test helper, and a
  **Breaking** changelog entry explaining how to migrate a deployment whose tokens lack `aud`, `typ`, or the expected
  `iss`.

### Move error handling to rootcause behind a std-error newtype

Discovery failures carry almost no diagnostics today. A proxy that answers with an HTML login page yields only
`error decoding response body: expected value at line 1 column 1`, without URL, status, content type, or body. Earlier
retry attempts are discarded. rootcause users see only the top message unless they register a `FollowSource` hook for
each error type. The experiment branch `experiment/rootcause` (`examples/metadata_rendering.rs`,
`examples/consumer_schemes.rs`) compares four representations across anyhow, eyre, `Box<dyn Error>`, tracing, and
rootcause consumers. A std-error newtype around a rootcause report is the only one that is no worse than today for any
consumer.

Decided design:

- One generic `error::Error<K>` with a kind enum per area: `AuthError = Error<AuthErrorKind>`,
  `ValidationPolicyError = Error<ValidationPolicyErrorKind>`, `InvalidServerUrlError = Error<InvalidServerUrlErrorKind>`.
  Users match on `err.kind()`. The kinds stay `#[non_exhaustive]` and keep the data callers match on (`role`, `reason`),
  but not their sources.
- `Display` is the kind's sanitized message, and `IntoResponse` uses only the kind, so metadata never reaches HTTP
  responses. Keep the tests that assert the provider address and role names stay out of response bodies.
- `source()` returns a lazily computed projection of the most relevant branch: a one-line summary of the last attempt
  built from its attachments, then the root cause's own chain. `Debug` renders the full report tree.
- Discovery and configuration errors carry full reports. Each attempt becomes a child in a `ReportCollection`, with typed
  attachments for provider, endpoint, attempt, elapsed time, HTTP status, content type, and a short response-body
  excerpt in an appendix. Foreign leaf errors such as `reqwest::Error` and `serde_json::Error` use a crate handler with
  `follow_source`, so their causes render without application hooks.
- Request-path errors (extraction, validation, roles) stay bare, holding only the kind and an optional source. rootcause
  runs every application-installed hook, such as backtrace capture, on each report creation, so creating a report per
  rejected request would add cost and amplify floods of invalid tokens. `into_report()` on a bare error creates the
  report at the caller.
- rootcause is always an internal dependency. A `rootcause` feature exposes `report()`, `into_report()`, and the
  attachment types for downcasting. Without the feature, rootcause is not part of the public API, so its 0.x releases do
  not force breaking releases of this crate.
- Remove snafu, `RefreshError::message`'s hand-rolled chain flattening, and the `Arc<reqwest::Error>` sources, which
  make `downcast_ref::<reqwest::Error>()` fail on today's `source()` chain.
- Changelog: a **Breaking** entry with migration steps. Matches change from `AuthError::X` to `err.kind()`, custom
  `TokenExtractor`s return `AuthErrorKind::X.into()`, and `KeycloakAuthStatus::Failure` holds the cloneable error
  instead of `Arc<AuthError>`. Document the `rootcause` feature in the README.

### Return a named type from `KeycloakAuthLayer::validate_raw_token`

It returns `(Option<HashMap<String, serde_json::Value>>, KeycloakToken<R, Extra>)`. Return a
struct with `token` and `raw_claims: Option<RawClaims>` fields instead.

## Worth considering

- Respond with `503 Service Unavailable` instead of `401 Unauthorized` for
  `AuthError::NoDecodingKeys`, which is a server-side outage rather than a client error.
- Replace the `KeycloakConfig::retry` tuple `(usize, u64)` with a named type that uses `Duration`.
- Rename `Profile::full_name` to `name`, matching Keycloak's standard claim.
- Enforce Keycloak Authorization Services policies with a separate authorization layer, giving the crate a
  Keycloak-specific feature beyond JWT validation. Keycloak only ships Java and JavaScript policy enforcers. Two modes:
  `TokenPermissions` checks the `authorization.permissions` claim of a locally validated RPT, and `RemoteDecision` asks
  Keycloak through the UMA grant with `response_mode=decision`. Keep authentication and authorization separate (`401`
  versus `403`, plus a distinct error for an unreachable policy endpoint), and give remote decisions their own timeout,
  health status, and optional cache. Leave out the UMA Protection API, permission tickets, and policy administration.
- Add an opt-out from rejecting credentials in more than one source with `AuthError::MultipleCredentialSources`, but
  only when users ask for it. 0.9.0 removed `TokenExtractionErrorPolicy` without a replacement. A non-breaking
  addition would be a `#[non_exhaustive]` `CredentialSourcePolicy` enum, set through a new
  `KeycloakAuthLayer` `credential_source_policy` setting: `SingleSource`, the default and current behavior, and
  `FirstToken`, which validates the first extracted token, skips unusable sources, and reports the first unusable one
  as `AuthError::TokenExtraction` if no extractor found a token. This restores the 0.8.4 `Fallback` default. Document
  `FirstToken` as non-compliant, and warn that components can then disagree about the token a request carries, such as
  a proxy that checks the `Authorization` header while the layer validates a query token.
- Add Standard Token Exchange V2 (RFC 8693) for downstream calls, with ergonomic audience reduction and downscoping. Use
  the discovered token endpoint and the caller's HTTP client, redact secrets and tokens from `Debug` and logs, keep the
  raw bearer token out of `KeycloakToken`, and do not retry ambiguous token requests. Do not support legacy V1.
