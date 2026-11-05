//! The Keycloak server base URL and the realm URLs derived from it.

use std::{fmt, str::FromStr};

use snafu::{ResultExt, ensure};
use url::Url;

use crate::error::{InvalidServerUrlError, invalid_server_url_error};

/// A Keycloak server base URL, such as `https://keycloak.example/` or
/// `https://keycloak.example/auth/`.
///
/// Construction rejects URLs that cannot serve as a base URL, such as `mailto:` URLs, so realm
/// paths can always be appended. A trailing slash is optional.
///
/// ```
/// use axum_keycloak_auth::instance::ServerUrl;
///
/// # fn run() -> Result<(), axum_keycloak_auth::error::InvalidServerUrlError> {
/// let server = ServerUrl::parse("https://keycloak.example/")?;
/// let same: ServerUrl = "https://keycloak.example/".parse()?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServerUrl(Url);

impl ServerUrl {
    /// Parses `input` with [`Url::parse`] and wraps the result.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidServerUrlError::Parse`] if `input` is not a valid URL, and
    /// [`InvalidServerUrlError::CannotBeABase`] if it cannot serve as a base URL.
    pub fn parse(input: &str) -> Result<Self, InvalidServerUrlError> {
        let url = Url::parse(input).context(invalid_server_url_error::ParseSnafu { input })?;
        Self::new(url)
    }

    /// Wraps an already parsed `url`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidServerUrlError::CannotBeABase`] if `url` cannot serve as a base URL.
    pub fn new(url: Url) -> Result<Self, InvalidServerUrlError> {
        ensure!(
            !url.cannot_be_a_base(),
            invalid_server_url_error::CannotBeABaseSnafu { url }
        );
        Ok(Self(url))
    }

    /// The wrapped URL, exactly as given to [`Self::new`].
    #[must_use]
    pub fn as_url(&self) -> &Url {
        &self.0
    }

    /// The base URL of `realm`, `<server>/realms/<realm>`. Keycloak also uses it as the issuer of
    /// the realm's tokens.
    pub(crate) fn realm_url(&self, realm: &str) -> Url {
        self.with_appended_path(&["realms", realm])
    }

    /// The URL of `realm`'s OIDC discovery document.
    pub(crate) fn discovery_url(&self, realm: &str) -> Url {
        self.with_appended_path(&["realms", realm, ".well-known", "openid-configuration"])
    }

    fn with_appended_path(&self, segments: &[&str]) -> Url {
        let mut url = self.0.clone();
        url.path_segments_mut()
            .expect("a `ServerUrl` can always serve as a base URL")
            // A trailing slash on the server URL (`https://host/auth/`) must not produce an empty
            // path segment (`/auth//realms/...`).
            .pop_if_empty()
            .extend(segments);
        url
    }
}

impl FromStr for ServerUrl {
    type Err = InvalidServerUrlError;

    /// Same as [`ServerUrl::parse`].
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

impl fmt::Display for ServerUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use assertr::prelude::*;
    use url::Url;

    use crate::error::InvalidServerUrlError;

    use super::ServerUrl;

    fn server_url(url: &str) -> ServerUrl {
        ServerUrl::parse(url).expect("the test URL must be a valid server URL")
    }

    #[test]
    fn realm_urls_are_derived_with_or_without_trailing_slash() {
        for (server, expected_realm_url) in [
            ("https://host", "https://host/realms/my-realm"),
            ("https://host/", "https://host/realms/my-realm"),
            ("https://host/auth", "https://host/auth/realms/my-realm"),
            ("https://host/auth/", "https://host/auth/realms/my-realm"),
        ] {
            let server_url = server_url(server);

            assert_that!(server_url.realm_url("my-realm").as_str())
                .with_subject_name(format!("realm URL for {server}"))
                .is_equal_to(expected_realm_url);
            assert_that!(server_url.discovery_url("my-realm").as_str())
                .with_subject_name(format!("discovery URL for {server}"))
                .is_equal_to(format!(
                    "{expected_realm_url}/.well-known/openid-configuration"
                ));
        }
    }

    #[test]
    fn parse_from_str_and_new_agree() {
        let input = "https://host/auth/";
        let parsed = server_url(input);

        assert_that!(input.parse::<ServerUrl>())
            .ok()
            .is_equal_to(&parsed);
        assert_that!(ServerUrl::new(
            Url::parse(input).expect("the test URL must parse")
        ))
        .ok()
        .is_equal_to(&parsed);
        assert_that!(parsed.as_url().as_str()).is_equal_to(input);
        assert_that!(parsed.to_string()).is_equal_to(input);
    }

    #[test]
    fn rejects_invalid_urls_and_names_them() {
        let error =
            ServerUrl::parse("keycloak.example").expect_err("a relative URL must be rejected");

        assert_that!(&error).is_equal_to(&InvalidServerUrlError::Parse {
            input: String::from("keycloak.example"),
            source: url::ParseError::RelativeUrlWithoutBase,
        });
        assert_that!(error.to_string())
            .contains("'keycloak.example'")
            .contains("is not a valid URL");
    }

    #[test]
    fn rejects_urls_that_cannot_serve_as_a_base_and_names_them() {
        let url = Url::parse("mailto:admin@example.com").expect("the mailto URL must parse");

        let error = ServerUrl::parse(url.as_str()).expect_err("a mailto URL must be rejected");

        assert_that!(&error).is_equal_to(&InvalidServerUrlError::CannotBeABase { url });
        assert_that!(error.to_string())
            .contains("'mailto:admin@example.com'")
            .contains("cannot serve as a base URL");
    }
}
