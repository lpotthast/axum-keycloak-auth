use keycloak::{KeycloakAdmin, KeycloakAdminToken, KeycloakTokenSupplier};
use testcontainers::{core::WaitFor, runners::AsyncRunner, GenericImage, RunnableImage};
use url::Url;

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

        // This is equivalent to the following cli command:
        // `docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:25.0.0 start-dev`
        let container: testcontainers::ContainerAsync<GenericImage> = RunnableImage::from(
            GenericImage::new("quay.io/keycloak/keycloak", "25.0.0")
                .with_env_var("KEYCLOAK_ADMIN", admin_user.as_str())
                .with_env_var("KEYCLOAK_ADMIN_PASSWORD", admin_password.as_str())
                .with_exposed_port(8080)
                .with_wait_for(WaitFor::message_on_stdout(
                    "Keycloak 25.0.0 on JVM (powered by Quarkus 3.8.5) started",
                ))
                .with_wait_for(WaitFor::message_on_stdout(
                    "Listening on: http://0.0.0.0:8080",
                ))
                .with_wait_for(WaitFor::message_on_stdout(
                    "Management interface listening on http://0.0.0.0:9000",
                )),
        )
        .with_args(vec!["start-dev".to_owned()])
        .start()
        .await
        .expect("Keycloak started");

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
        let client = reqwest::Client::new();
        let admin_token = KeycloakAdminToken::acquire(
            self.url.as_str(),
            &self.admin_user,
            &self.admin_password,
            &client,
        )
        .await
        .expect("Correct credentials");

        KeycloakAdmin::new(self.url.as_str(), admin_token, client)
    }

    pub async fn perform_password_login(
        &self,
        username: &str,
        password: &str,
        realm: &str,
        client_id: &str,
    ) -> String {
        let client = reqwest::Client::new();

        let token = KeycloakAdminToken::acquire_custom_realm(
            self.url.as_str(),
            username,
            password,
            realm,
            client_id,
            "password",
            &client,
        )
        .await
        .unwrap();

        let access_token = token.get(self.url.as_str()).await.unwrap();

        tracing::info!(access_token, "Login successful.");
        access_token
    }
}
