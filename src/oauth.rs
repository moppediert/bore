use axum::extract::{Json, Path, Query, State};
use url::Url;
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::str::FromStr;

use anyhow::Result;
use axum::routing::get;
use axum::Router;
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, StandardRevocableToken, TokenResponse, TokenUrl, IntrospectionUrl, TokenIntrospectionResponse,
};

use oauth2::reqwest::{http_client, async_http_client};
use serde::Deserialize;

// TODO: handle error case, e.g. when user denies login
#[derive(Deserialize)]
struct AuthResult {
    code: String,
    state: String,
}

#[derive(Clone)]
struct AuthState {
    client: BasicClient,
    csrf_secret: String,
    pkce_code_verifier: String,
}

/// Authenticate with Oauth2 Authorization Code Flow with PKCE
pub async fn auth(
    client_id: String,
    client_secret: Option<String>,
    auth_url: String,
    token_url: String,
) -> Result<String> {
    // Create an OAuth2 client
    let client = BasicClient::new(
        ClientId::new(client_id),
        client_secret.map(ClientSecret::new), // client secret is optional
        AuthUrl::new(auth_url)?,
        Some(TokenUrl::new(token_url)?),
    )
    .set_redirect_uri(RedirectUrl::new("http://localhost:8080".to_string())?);

    // Generate a PKCE challenge.
    let (code_challenge, code_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL.
    let (auth_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("email".to_string()))
        .set_pkce_challenge(code_challenge)
        .url();

    println!("Open this URL to authenticate: {}", auth_url);
    println!("Own state: {}", csrf_state.secret());

    async fn auth_handler(auth_result: Query<AuthResult>, State(auth_state): State<AuthState>) {
        assert!(auth_result.state == auth_state.csrf_secret, "State received from OAuth provider does not match initial state, authentication aborted.");

        let auth_url = env::var("AUTH_URL").unwrap();
        let keycloak_realm = env::var("KEYCLOAK_REALM").unwrap();

        let token = auth_state
            .client
            .exchange_code(AuthorizationCode::new(auth_result.code.clone()))
            .set_pkce_verifier(PkceCodeVerifier::new(auth_state.pkce_code_verifier))
            .request_async(async_http_client).await.unwrap();

        println!("Access token: {}", token.access_token().secret());
        let client = auth_state.client;
        let client = client.set_introspection_uri(IntrospectionUrl::new(format!("https://{}/auth/realms/{}/protocol/openid-connect/token/introspect", auth_url, keycloak_realm)).unwrap());

        println!("Introspection uri: {}", client.introspection_url().unwrap().as_str());
        let result = client.introspect(token.access_token()).unwrap().request_async(async_http_client);
        let result = result.await.err().unwrap();
        println!("------> {}", result);
        // assert!(result.active(), "Access token inactive, authentication aborted");
    }

    let auth_state = AuthState {
        client,
        csrf_secret: csrf_state.secret().to_string(),
        pkce_code_verifier: code_verifier.secret().to_string(),
    };

    let app = Router::new().route("/", get(auth_handler)).with_state(auth_state);

    let server = axum::Server::bind(&SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 8080))
        .serve(app.into_make_service());
    server.await?;

    Ok("".to_string())
}
