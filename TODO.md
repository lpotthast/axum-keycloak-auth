# TODO

## Next breaking release

### Type `KeycloakConfig::server` as `ServerUrl`

`KeycloakConfig::server` is a plain `Url`, so a URL that cannot serve as a base URL (such as a
`mailto:` URL) is only rejected when it is used. `KeycloakAuthInstance::new` and
`KeycloakConfig::issuer` therefore panic on it, and only `KeycloakAuthInstanceBuilder::build` can
report it as an error. Make the crate-internal `ServerUrl` public and use it as the field type, so
that an invalid URL is rejected once, at construction, through `ServerUrl::new` and its
`InvalidServerUrlError`. Both panics then disappear, and `build` becomes infallible.

### Require a caller-supplied HTTP client

All documentation already creates instances through `KeycloakAuthInstance::builder` with an
explicit `reqwest::Client` and announces that a future release will require it. Make the client a
required argument of `KeycloakAuthInstance::builder`, and remove `KeycloakAuthInstance::new` and
the crate's default client. Timeouts, proxies, and the TLS backend are then entirely the
application's choice, so the `default-tls` and `rustls-tls` features can go away. Consider
re-exporting `reqwest` so that applications cannot pick an incompatible major version.

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

### Remove compatibility leftovers

- Remove the deprecated `decode` module. Its types live in `token`.
- Remove the `oidc_discovery` module, which only re-exports `RequestError`. Export `RequestError`
  from `error` instead.
- Remove `AuthError::NoJwkSetDiscovery` and `AuthError::CreateDecodingKey`. Nothing constructs them
  anymore. Discovery reports `NoDecodingKeys` instead.
- Make the `oidc` module private. No public API uses its discovery-document models, and they are
  exempt from the missing-documentation lint.

### Mark `AuthError` as `#[non_exhaustive]`

`AuthError` is the only public error enum that is still exhaustive, so adding a variant is a
breaking change today. `ValidationPolicyError` and the configuration enums already are
non-exhaustive.

### Make `KeycloakAuthInstance::is_operational` synchronous

It only reads in-memory state and is `async` solely to keep its 0.8.3 signature (see the
`clippy::unused_async` allowance in `instance.rs`). `operational_status`, which reads the same
state, is already synchronous.

### Signal an absent credential source without `AuthError`

`TokenExtractor::extract` reports "no credential here" through a fixed set of `AuthError` variants
(`MissingToken`, `MissingAuthorizationHeader`, `MissingQueryParams`, `MissingTokenQueryParam`),
which `extract_jwt` must recognize by name. Return `Result<Option<ExtractedToken>, AuthError>`
instead, so that `Ok(None)` means absent and every error means present but unusable. This also
removes the special case in `QueryParamTokenExtractor::extract`.

### Reject inconsistent layer configuration when building the layer

A validation policy that requires an audience while none is configured rejects every token, but
it is only logged as a warning when the first service or validator is created (see `validator()`
in `layer.rs`). Make building a `KeycloakAuthLayer` fallible and return this as an error.

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
- Add Standard Token Exchange V2 (RFC 8693) for downstream calls, with ergonomic audience reduction and downscoping. Use
  the discovered token endpoint and the caller's HTTP client, redact secrets and tokens from `Debug` and logs, keep the
  raw bearer token out of `KeycloakToken`, and do not retry ambiguous token requests. Do not support legacy V1.
