use axum::extract::{Json, Path, Query};
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr, TcpListener};

use anyhow::Result;
use axum::routing::get;
use axum::Router;
use oauth2::basic::BasicClient;
use oauth2::reqwest::http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    Scope, StandardRevocableToken, TokenResponse, TokenUrl,
};

use serde::Deserialize;
use url::Url;

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
    );

    // Set the URL the user will be redirected to after the authorization process.
    // Later on we will listen at this port to get the response from Auth Server
    let client = client.set_redirect_uri(RedirectUrl::new("http://localhost:8080".to_string())?);

    // Generate a PKCE challenge.
    let (code_challenge, code_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL.
    let (auth_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("email".to_string()))
        .set_pkce_challenge(code_challenge)
        .url();

    // This is the URL you should redirect the user to, in order to trigger the authorization
    // process.
    println!("Open this URL to authenticate: {}", auth_url);

    #[derive(Deserialize)]
    struct AuthResult {
        code: String,
        state: String,
    }

    async fn path(auth_result: Query<AuthResult>) {
        println!("Received code: {}", auth_result.code);
        println!("Received state: {}", auth_result.state);
    }

    let app = Router::new().route("/", get(path));

    let server = axum::Server::bind(&SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 8080))
        .serve(app.into_make_service());
    server.await?;

    Ok("".to_string())
}
