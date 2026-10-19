//! The Keycloak server base URL and the realm URLs derived from it.

use url::Url;

use crate::error::InvalidServerUrlError;

/// A Keycloak server base URL, such as `https://host/` or `https://host/auth/`.
///
/// Construction rejects "cannot-be-a-base" URLs, such as `mailto:` URLs, so realm paths can always
/// be appended. A trailing slash is optional.
#[derive(Debug, Clone)]
pub(crate) struct ServerUrl(Url);

impl ServerUrl {
    /// Wraps `url`.
    ///
    /// # Errors
    ///
    /// Returns an [`InvalidServerUrlError`] if `url` cannot serve as a base URL.
    pub(crate) fn new(url: Url) -> Result<Self, InvalidServerUrlError> {
        if url.cannot_be_a_base() {
            return Err(InvalidServerUrlError::new(url));
        }
        Ok(Self(url))
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

#[cfg(test)]
mod tests {
    use assertr::prelude::*;
    use url::Url;

    use super::ServerUrl;

    fn server_url(url: &str) -> ServerUrl {
        ServerUrl::new(Url::parse(url).expect("the test URL must parse"))
            .expect("the test URL must serve as a base URL")
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
    fn rejects_urls_that_cannot_serve_as_a_base_and_names_them() {
        let url = Url::parse("mailto:admin@example.com").expect("the mailto URL must parse");

        let error = ServerUrl::new(url.clone()).expect_err("a mailto URL must be rejected");

        assert_that!(error.url()).is_equal_to(&url);
        assert_that!(error.to_string())
            .contains("'mailto:admin@example.com'")
            .contains("cannot serve as a base URL");
    }
}
