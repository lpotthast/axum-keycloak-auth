//! Hermetic test infrastructure shared by the crate's unit tests.
//!
//! Everything here is deterministic and local: committed throwaway keys instead of generated ones,
//! a manual clock instead of the wall clock, and in-process doubles instead of a real Keycloak.
//! The Keycloak integration test in `tests/` covers the real provider.
//!
//! All fixtures describe one realm: [`TEST_REALM`] on [`test_server_url`], issuing tokens for
//! [`TEST_AUDIENCE`] signed by [`RSA_KEY_A`] under [`TEST_KID`].
//!
//! # Choosing a fixture
//!
//! - Token contents: [`keycloak_claims`], [`claims_with`], and [`claims_without`].
//! - Signatures and key material: [`RSA_KEY_A`], [`RSA_KEY_B`], [`EC_KEY_A`], and
//!   [`signed_token`].
//! - The validation pipeline without I/O: [`StaticKeySource`] with [`legacy_policy`] or
//!   [`strict_policy`].
//! - The middleware or layer without I/O: [`offline_layer`] or [`offline_instance`], driven by
//!   [`bearer_request`] or [`anonymous_request`].
//! - Discovery, refresh, and provider failures: [`MockOidcServer`] with [`config_for`] or
//!   [`discovered_instance`].
//! - Anything time-dependent: [`ManualClock`] and [`validation_time`].
//! - Logging behavior: [`CapturedLogs`] and [`assert_logged_iff`].
//! - Concurrency, without hanging on a regression: [`within_test_timeout`] and [`wait_until`].

mod claims;
mod clock;
mod instances;
mod key_source;
mod keys;
mod logs;
mod middleware;
mod mock_provider;
mod policy;
mod wait;

pub(crate) use claims::{
    Claims, TEST_AUDIENCE, TEST_ISSUER, TEST_KID, TEST_REALM, claims_with, claims_without,
    keycloak_claims, signed_token, test_server_url, validation_time,
};
pub(crate) use clock::ManualClock;
pub(crate) use instances::{
    config_for, discovered_data_at, discovered_instance, offline_instance, offline_instance_at,
    refresh_policy_without_jitter, static_discovered_data, wait_for_discovery_completion,
};
pub(crate) use key_source::StaticKeySource;
pub(crate) use keys::{EC_KEY_A, RSA_KEY_A, RSA_KEY_B};
pub(crate) use logs::{CapturedLogs, assert_logged_iff};
pub(crate) use middleware::{anonymous_request, bearer_request, offline_layer, response_text};
pub(crate) use mock_provider::{MockOidcServer, MockResponse};
pub(crate) use policy::{legacy_policy, strict_policy};
pub(crate) use wait::{TEST_TIMEOUT, wait_until, within_test_timeout};
