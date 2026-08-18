use keycloak::{
    KeycloakAdmin, KeycloakAdminToken, KeycloakTokenSupplier, prelude::reqwest::Client,
};
use testcontainers::{
    GenericImage, ImageExt,
    core::{ContainerPort, WaitFor},
    runners::AsyncRunner,
};
use url::Url;

const KEYCLOAK_VERSION: &str = "26.7.1";
const KEYCLOAK_QUARKUS_VERSION: &str = "3.33.2.1";

#[allow(dead_code)]
pub struct KeycloakContainer {
    container: testcontainers::ContainerAsync<GenericImage>,
    pub admin_user: String,
    pub admin_password: String,
    pub port: u16,
    pub management_port: u16,
    pub url: Url,
}

impl KeycloakContainer {
    pub async fn start() -> Self {
        tracing::info!("Starting Keycloak...");

        let admin_user = "admin".to_owned();
        let admin_password = "admin".to_owned();

        // This setup is roughly equivalent to the following cli command:
        // `podman run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:26.7.1 start-dev`

        let keycloak_image = GenericImage::new("quay.io/keycloak/keycloak", KEYCLOAK_VERSION)
            .with_exposed_port(ContainerPort::Tcp(8080))
            .with_wait_for(WaitFor::message_on_stdout(format!(
                "Keycloak {KEYCLOAK_VERSION} on JVM (powered by Quarkus {KEYCLOAK_QUARKUS_VERSION}) started"
            )))
            .with_wait_for(WaitFor::message_on_stdout(
                "Listening on: http://0.0.0.0:8080",
            ));

        let container_request = keycloak_image
            .with_env_var("KEYCLOAK_ADMIN", admin_user.as_str())
            .with_env_var("KEYCLOAK_ADMIN_PASSWORD", admin_password.as_str())
            .with_cmd(["start-dev"]);

        let container = container_request.start().await.expect("Keycloak started");

        let port = container
            .get_host_port_ipv4(8080)
            .await
            .expect("Keycloak to export port 8080");

        let management_port = container
            .get_host_port_ipv4(8080)
            .await
            .expect("Keycloak to export port 9000");

        let url = Url::parse(format!("http://127.0.0.1:{}", port).as_str()).unwrap();
        tracing::info!(available_at = ?url, "Keycloak started.");

        Self {
            container,
            admin_user,
            admin_password,
            port,
            management_port,
            url,
        }
    }

    pub async fn admin_client(&self) -> KeycloakAdmin {
        let keycloak_url = self.url.as_str().trim_end_matches('/');
        let client = Client::new();
        let admin_token = KeycloakAdminToken::acquire(
            keycloak_url,
            &self.admin_user,
            &self.admin_password,
            &client,
        )
        .await
        .expect("Correct credentials");

        KeycloakAdmin::new(keycloak_url, admin_token, client)
    }

    pub async fn perform_password_login(
        &self,
        username: &str,
        password: &str,
        realm: &str,
        client_id: &str,
    ) -> String {
        let keycloak_url = self.url.as_str().trim_end_matches('/');
        let client = Client::new();

        let token = KeycloakAdminToken::acquire_custom_realm(
            keycloak_url,
            username,
            password,
            realm,
            client_id,
            "password",
            &client,
        )
        .await
        .unwrap();

        let access_token = token.get(keycloak_url).await.unwrap();

        tracing::info!(access_token, "Login successful.");
        access_token
    }
}
