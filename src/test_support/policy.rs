use crate::validation::{ValidationPolicy, ValidationPolicyBuilder};

/// The audience carried by the fixture tokens from [`super::jwt::keycloak_claims`].
fn audiences() -> [String; 1] {
    [String::from("account")]
}

/// The legacy preset completed with the audiences of the test fixtures.
pub(crate) fn legacy_policy() -> ValidationPolicyBuilder {
    ValidationPolicy::legacy().expected_audiences(audiences().to_vec())
}

/// The strict preset completed with the audiences and issuer of the test fixtures.
pub(crate) fn strict_policy() -> ValidationPolicyBuilder {
    ValidationPolicy::strict()
        .expected_audiences(audiences().to_vec())
        .expected_issuers(vec![String::from(
            "https://issuer.example/realms/test-realm",
        )])
}
