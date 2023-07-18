use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

use anyhow::Result;
use oauth2::basic::BasicClient;
use oauth2::reqwest::http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    Scope, StandardRevocableToken, TokenResponse, TokenUrl,
};

use url::Url;

/// Authenticate with oauth2 standard flow
pub fn auth(
    client_id: String,
    client_secret: Option<String>,
    auth_url: String,
    token_url: String,
) -> Result<String> {
    // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and
    // token URL.
    let client = BasicClient::new(
        ClientId::new(client_id),
        client_secret.map(ClientSecret::new),
        AuthUrl::new(auth_url)?,
        Some(TokenUrl::new(token_url)?),
    )
    // Set the URL the user will be redirected to after the authorization process.
    .set_redirect_uri(RedirectUrl::new("http://localhost:8080".to_string())?);

    // Generate a PKCE challenge.
    let (pkce_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL.
    let (auth_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        // Set the desired scopes.
        .add_scope(Scope::new("email".to_string()))
        // Set the PKCE code challenge.
        .set_pkce_challenge(pkce_challenge)
        .url();

    // This is the URL you should redirect the user to, in order to trigger the authorization
    // process.
    println!("Open this URL to authenticate: {}", auth_url);

    // Once the user has been redirected to the redirect URL, you'll have access to the
    // authorization code. For security reasons, your code should verify that the `state`
    // parameter returned by the server matches `csrf_state`.

    // Now you can trade it for an access token.
    // let token_result = client
    //     .exchange_code(AuthorizationCode::new(
    //         "some authorization code".to_string(),
    //     ))
    //     // Set the PKCE code verifier.
    //     .set_pkce_verifier(pkce_verifier)
    //     .request(http_client)?;

    // println!("{}", token_result.access_token().secret());

    // A very naive implementation of the redirect server.
    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();
    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            let code;
            let state;
            {
                let mut reader = BufReader::new(&stream);

                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();

                let redirect_url = request_line.split_whitespace().nth(1).unwrap();
                let url = Url::parse(&("http://localhost".to_string() + redirect_url)).unwrap();

                let code_pair = url
                    .query_pairs()
                    .find(|pair| {
                        let &(ref key, _) = pair;
                        key == "code"
                    })
                    .unwrap();

                let (_, value) = code_pair;
                code = AuthorizationCode::new(value.into_owned());

                let state_pair = url
                    .query_pairs()
                    .find(|pair| {
                        let &(ref key, _) = pair;
                        key == "state"
                    })
                    .unwrap();

                let (_, value) = state_pair;
                state = CsrfToken::new(value.into_owned());
            }

            let message = "Go back to your terminal :)";
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                message.len(),
                message
            );
            stream.write_all(response.as_bytes()).unwrap();

            println!("Google returned the following code:\n{}\n", code.secret());
            println!(
                "Google returned the following state:\n{} (expected `{}`)\n",
                state.secret(),
                csrf_state.secret()
            );

            // Exchange the code with a token.
            let token_response = client
                .exchange_code(code)
                .set_pkce_verifier(pkce_code_verifier)
                .request(http_client);

            println!(
                "Google returned the following token:\n{:?}\n",
                token_response
            );

            // Revoke the obtained token
            let token_response = token_response.unwrap();
            let token_to_revoke: StandardRevocableToken = match token_response.refresh_token() {
                Some(token) => token.into(),
                None => token_response.access_token().into(),
            };

            client
                .revoke_token(token_to_revoke)
                .unwrap()
                .request(http_client)
                .expect("Failed to revoke token");

            // The server will terminate itself after revoking the token.
            break;
        } else {
        }
    }

    Ok("".to_string())
}
