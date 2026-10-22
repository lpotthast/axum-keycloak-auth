//! The exported role macros, used the way an application handler uses them: from outside the
//! crate, returning the role rejection as the handler's response.

use assertr::prelude::*;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use axum_keycloak_auth::{role::KeycloakRole, token::KeycloakToken};

fn token() -> KeycloakToken<String, ()> {
    KeycloakToken {
        expires_at: time::OffsetDateTime::UNIX_EPOCH,
        issued_at: time::OffsetDateTime::UNIX_EPOCH,
        jwt_id: String::from("test-token"),
        issuer: String::from("https://keycloak.example/realms/test"),
        audience: vec![String::from("account")],
        subject: String::from("test-user"),
        authorized_party: String::from("account"),
        roles: vec![
            KeycloakRole::Realm {
                role: String::from("realm-role"),
            },
            KeycloakRole::Client {
                client: String::from("account"),
                role: String::from("client-role"),
            },
        ],
        extra: (),
    }
}

fn expect_multiple(token: &KeycloakToken<String, ()>, roles: &[&str]) -> Response {
    axum_keycloak_auth::expect_roles!(token, roles);
    StatusCode::NO_CONTENT.into_response()
}

fn expect_one(token: &KeycloakToken<String, ()>, role: &str) -> Response {
    axum_keycloak_auth::expect_role!(token, role);
    StatusCode::NO_CONTENT.into_response()
}

fn forbid_multiple(token: &KeycloakToken<String, ()>, roles: &[&str]) -> Response {
    axum_keycloak_auth::not_expect_roles!(token, roles);
    StatusCode::NO_CONTENT.into_response()
}

fn forbid_one(token: &KeycloakToken<String, ()>, role: &str) -> Response {
    axum_keycloak_auth::not_expect_role!(token, role);
    StatusCode::NO_CONTENT.into_response()
}

#[test]
fn expect_roles_macro_returns_success_or_the_role_rejection() {
    let token = token();

    assert_that!(expect_multiple(&token, &["realm-role", "client-role"]).status())
        .is_equal_to(StatusCode::NO_CONTENT);
    assert_that!(expect_multiple(&token, &["missing-role"]).status())
        .is_equal_to(StatusCode::FORBIDDEN);
}

#[test]
fn expect_role_macro_returns_success_or_the_role_rejection() {
    let token = token();

    assert_that!(expect_one(&token, "client-role").status()).is_equal_to(StatusCode::NO_CONTENT);
    assert_that!(expect_one(&token, "missing-role").status()).is_equal_to(StatusCode::FORBIDDEN);
}

#[test]
fn not_expect_roles_macro_returns_success_or_the_role_rejection() {
    let token = token();

    assert_that!(forbid_multiple(&token, &["absent-role"]).status())
        .is_equal_to(StatusCode::NO_CONTENT);
    assert_that!(forbid_multiple(&token, &["realm-role"]).status())
        .is_equal_to(StatusCode::FORBIDDEN);
}

#[test]
fn not_expect_role_macro_returns_success_or_the_role_rejection() {
    let token = token();

    assert_that!(forbid_one(&token, "absent-role").status()).is_equal_to(StatusCode::NO_CONTENT);
    assert_that!(forbid_one(&token, "client-role").status()).is_equal_to(StatusCode::FORBIDDEN);
}
