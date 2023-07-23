use axum::extract::{Json, Path, Query, State};
use axum::http::Request;
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::str::FromStr;
use url::Url;

use anyhow::Result;
use axum::routing::get;
use axum::Router;
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IntrospectionUrl,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, StandardRevocableToken,
    TokenIntrospectionResponse, TokenResponse, TokenUrl,
};

use oauth2::reqwest::{async_http_client, http_client};
use reqwest;
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
        .add_scope(Scope::new("openid".to_string()))
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
            .request_async(async_http_client)
            .await
            .unwrap();

        println!("Access token: {}", token.access_token().secret());

        let token_string = token.access_token().secret();

        let client = reqwest::Client::builder().build().unwrap();
        let response = client.get(format!("{}/realms/{}/protocol/openid-connect/userinfo", auth_url, keycloak_realm))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", token_string))
        .send().await.unwrap();
        println!("Response: {}", response.text().await.unwrap());
    }

    let auth_state = AuthState {
        client,
        csrf_secret: csrf_state.secret().to_string(),
        pkce_code_verifier: code_verifier.secret().to_string(),
    };

    let app = Router::new()
        .route("/", get(auth_handler))
        .with_state(auth_state);

    let server = axum::Server::bind(&SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 8080))
        .serve(app.into_make_service());
    server.await?;

    Ok("".to_string())
}
