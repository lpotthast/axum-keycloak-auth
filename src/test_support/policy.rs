//! Validation policy presets completed for the fixture realm.

use crate::validation::{ValidationPolicy, ValidationPolicyBuilder};

use super::{TEST_AUDIENCE, TEST_ISSUER};

/// The legacy preset, expecting [`TEST_AUDIENCE`].
pub(crate) fn legacy_policy() -> ValidationPolicyBuilder {
    ValidationPolicy::legacy().expected_audiences([TEST_AUDIENCE])
}

/// The strict preset, expecting [`TEST_AUDIENCE`] and [`TEST_ISSUER`].
pub(crate) fn strict_policy() -> ValidationPolicyBuilder {
    ValidationPolicy::strict()
        .expected_audiences([TEST_AUDIENCE])
        .expected_issuers([TEST_ISSUER])
}
