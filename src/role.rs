//! Role types, role checks, and handler-return convenience macros.

use std::fmt::{Debug, Display};

use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

/// A role value parsed from a role name in a Keycloak token.
///
/// Use `String` unless the application benefits from a domain-specific enum. A custom type must
/// preserve unknown names through its [`From<String>`] implementation if those roles need to
/// remain observable.
pub trait Role: Debug + Display + Clone + PartialEq + Eq + Send + Sync + From<String> {}

/// Uses the role name unchanged.
impl Role for String {}

/// A realm or client role.
///
/// Its Serde representation is internally tagged with `"type": "Realm"` or `"type": "Client"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum KeycloakRole<R: Role> {
    /// A realm role.
    Realm {
        /// Role value.
        role: R,
    },
    /// A client role.
    Client {
        /// Keycloak client ID.
        client: String,
        /// Role value.
        role: R,
    },
}

impl<R: Role> KeycloakRole<R> {
    /// Returns the role value without its realm or client scope.
    pub fn role(&self) -> &R {
        match self {
            KeycloakRole::Realm { role } | KeycloakRole::Client { client: _, role } => role,
        }
    }
}

/// Returns the number of role names contained in a claim representation.
///
/// [`ExtractRoles`] uses this to reserve the target vector's capacity.
pub trait NumRoles {
    /// Returns the number of contained roles.
    fn num_roles(&self) -> usize;
}

impl<T: NumRoles> NumRoles for Option<T> {
    fn num_roles(&self) -> usize {
        self.as_ref().map_or(0, NumRoles::num_roles)
    }
}

/// Appends roles from a claim representation to a target collection.
pub trait ExtractRoles<R: Role> {
    /// Consumes the representation and appends its roles to `target`.
    fn extract_roles(self, target: &mut Vec<KeycloakRole<R>>);
}

impl<R: Role, T: ExtractRoles<R>> ExtractRoles<R> for Option<T> {
    fn extract_roles(self, target: &mut Vec<KeycloakRole<R>>) {
        if let Some(inner) = self {
            inner.extract_roles(target);
        }
    }
}

impl<R: Role, A, B> ExtractRoles<R> for (A, B)
where
    A: NumRoles + ExtractRoles<R>,
    B: NumRoles + ExtractRoles<R>,
{
    fn extract_roles(self, target: &mut Vec<KeycloakRole<R>>) {
        target.reserve(self.0.num_roles() + self.1.num_roles());
        self.0.extract_roles(target);
        self.1.extract_roles(target);
    }
}

/// Checks required and forbidden role values on a token-like value.
///
/// [`KeycloakToken`](crate::token::KeycloakToken) checks ignore whether a role came from the realm
/// or a client. Inspect [`KeycloakToken::roles`](crate::token::KeycloakToken::roles) directly when
/// role scope matters.
pub trait ExpectRoles<R: Role> {
    /// Error returned when a role check fails.
    type Rejection: IntoResponse;

    /// Verifies that all given roles are present.
    ///
    /// # Errors
    ///
    /// Returns a rejection if any expected role is missing.
    fn expect_roles<I: Into<R> + Clone>(&self, roles: &[I]) -> Result<(), Self::Rejection>;

    /// Verifies that none of the given roles are present.
    ///
    /// # Errors
    ///
    /// Returns a rejection if any unexpected role is present.
    fn not_expect_roles<I: Into<R> + Clone>(&self, roles: &[I]) -> Result<(), Self::Rejection>;
}

#[macro_export]
/// Requires every listed role or returns its rejection as an Axum response.
///
/// This macro returns early on failure, so the surrounding function must return an
/// [`axum::response::Response`]. Use [`role::ExpectRoles`](crate::role::ExpectRoles) directly when
/// another return type is needed.
///
/// ```
/// use axum::{
///     Extension,
///     response::{IntoResponse, Response},
/// };
/// use axum_keycloak_auth::{expect_roles, token::KeycloakToken};
///
/// async fn admin_only(Extension(token): Extension<KeycloakToken<String>>) -> Response {
///     expect_roles!(&token, &["administrator", "auditor"]);
///     "Welcome, administrator.".into_response()
/// }
/// ```
macro_rules! expect_roles {
    ($token: expr, $roles: expr) => {
        if let Err(err) = $crate::role::ExpectRoles::expect_roles($token, $roles) {
            return $crate::__private::IntoResponse::into_response(err);
        }
    };
}

#[macro_export]
/// Requires one role or returns its rejection as an Axum response.
///
/// This macro returns early on failure, so the surrounding function must return an
/// [`axum::response::Response`]. Use [`role::ExpectRoles`](crate::role::ExpectRoles) directly when
/// another return type is needed.
macro_rules! expect_role {
    ($token: expr, $role: expr) => {
        if let Err(err) = $crate::role::ExpectRoles::expect_roles($token, &[$role]) {
            return $crate::__private::IntoResponse::into_response(err);
        }
    };
}

#[macro_export]
/// Forbids any listed role or returns its rejection as an Axum response.
///
/// This macro returns early on failure, so the surrounding function must return an
/// [`axum::response::Response`]. Use [`role::ExpectRoles`](crate::role::ExpectRoles) directly when
/// another return type is needed.
macro_rules! not_expect_roles {
    ($token: expr, $roles: expr) => {
        if let Err(err) = $crate::role::ExpectRoles::not_expect_roles($token, $roles) {
            return $crate::__private::IntoResponse::into_response(err);
        }
    };
}

#[macro_export]
/// Forbids one role or returns its rejection as an Axum response.
///
/// This macro returns early on failure, so the surrounding function must return an
/// [`axum::response::Response`]. Use [`role::ExpectRoles`](crate::role::ExpectRoles) directly when
/// another return type is needed.
macro_rules! not_expect_role {
    ($token: expr, $role: expr) => {
        if let Err(err) = $crate::role::ExpectRoles::not_expect_roles($token, &[$role]) {
            return $crate::__private::IntoResponse::into_response(err);
        }
    };
}
