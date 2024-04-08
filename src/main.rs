
use std::env;
use std::net::SocketAddr;
use std::str::FromStr;

use axum::{
    http::Request,
    routing::{get, post},
    Router,
    response::Response,
    middleware::Next, body::Body,
};

use axum::{
    response::IntoResponse,
    response::Html,
    extract::Multipart,
};

use axum::http::{
    StatusCode,
    HeaderMap,
    HeaderName,
};

use base64::prelude::*;

use tower_http::services::ServeDir;

use ed25519_dalek::{SigningKey, Signer};


static RESPONSE_HEADER_CSP: &str = "default-src https:; base-uri 'none'; form-action https:; frame-ancestors 'none';";
static RESPONSE_HEADER_X_FRAME_OPTIONS: &str = "DENY";
static RESPONSE_HEADER_X_CONTENT_TYPE_OPTIONS: &str = "nosniff";


#[derive(serde::Deserialize)]
struct ApiResponse {
    success: bool,
}


/// Middleware to add global headers to all responses.
async fn add_global_headers(req: Request<Body>, next: Next) -> Response {
    let mut res = next.run(req).await;
    let headers = res.headers_mut();
    headers.append("content-security-policy", RESPONSE_HEADER_CSP.parse().unwrap());
    headers.append("x-frame-options", RESPONSE_HEADER_X_FRAME_OPTIONS.parse().unwrap());
    headers.append("x-content-type-options", RESPONSE_HEADER_X_CONTENT_TYPE_OPTIONS.parse().unwrap());
    res
}

async fn handler_404() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "404 Not Found").into_response()
}

async fn handler_root() -> impl IntoResponse {
    let recaptcha_site_key = env::var("RECAPTCHA_SITE_KEY").unwrap_or("".to_string());
    let html = format!(r#"
<!DOCTYPE html>
<html>
    <head>
    <meta charset="utf-8">
    <title>CAPTCHA</title>
    <meta name="viewport" content="width=device-width">
    <link rel="stylesheet" href="/assets/main.css">
    <script src="/assets/main.js"></script>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    </head>
    <body>
    <form action="/submit" method="POST" enctype="multipart/form-data">
        <div class="g-recaptcha" data-sitekey="{recaptcha_site_key}" data-callback="captchaCallback"></div>
        <input id="input-request-token" type="hidden" name="request-token"/>
        <input id="input-redirect-url" type="hidden" name="redirect-url"/>
        <button id="button-submit" type="submit" disabled>Next</button>
    </form>
    </body>
</html>
"#);
    //
    (StatusCode::OK, Html(html)).into_response()
}

async fn handler_submit(
    mut multipart: Multipart,
) -> impl IntoResponse {
    let private_key = env::var("PRIVATE_KEY").unwrap_or("".to_string());
    if private_key.is_empty() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "Private key is not set.").into_response();
    }

    let private_key = if let Ok(private_key) = BASE64_STANDARD.decode(private_key) {
        private_key
    } else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "Invalid private key.").into_response();
    };

    if private_key.len() != 32 {
        return (StatusCode::INTERNAL_SERVER_ERROR, "Invalid private key length.").into_response();
    }

    let private_key: [u8; 32] = private_key[0..32].try_into().unwrap();

    let recaptcha_secret = env::var("RECAPTCHA_SECRET").unwrap_or("".to_string());
    if recaptcha_secret.is_empty() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "Recaptcha secret is not set.").into_response();
    }

    let mut request_token = None;
    let mut redirect_url = None;
    let mut recaptcha_response = None;
    while let Ok(field) = multipart.next_field().await {
        let field = if let Some(field) = field {
            field
        } else {
            break;
        };

        let field_name = field.name().unwrap_or("");
        let field_name = field_name.to_lowercase();
        if field_name.is_empty() {
            continue;
        }

        if field_name == "g-recaptcha-response" {
            let response = field.text().await.unwrap_or("".to_string());
            if response.is_empty() {
                return (StatusCode::BAD_REQUEST, "Recaptcha response is empty.").into_response();
            }
            recaptcha_response = Some(response);
        } else if field_name == "request-token" {
            let token = field.text().await.unwrap_or("".to_string());
            if token.is_empty() {
                return (StatusCode::BAD_REQUEST, "Request token is empty.").into_response();
            }
            request_token = Some(token);
        } else if field_name == "redirect-url" {
            let url = field.text().await.unwrap_or("".to_string());
            if url.is_empty() {
                return (StatusCode::BAD_REQUEST, "Redirect URL is empty.").into_response();
            }
            redirect_url = Some(url);
        }
    }

    if let None = recaptcha_response {
        return (StatusCode::BAD_REQUEST, "Recaptcha response is missing.").into_response();
    }

    let request_token = if let Some(request_token) = request_token {
        request_token
    } else {
        return (StatusCode::BAD_REQUEST, "Request token is missing.").into_response();
    };

    let redirect_url = if let Some(redirect_url) = redirect_url {
        redirect_url
    } else {
        return (StatusCode::BAD_REQUEST, "Redirect URL is missing.").into_response();
    };

    let api_url = "https://www.google.com/recaptcha/api/siteverify";

    let recaptcha_response = recaptcha_response.unwrap();

    let api_params = (
        ("secret", recaptcha_secret.as_str()),
        ("response", recaptcha_response.as_str()),
    );
    
    let client = reqwest::Client::new();

    let response = client.post(api_url)
        .form(&api_params)
        .send()
        .await;

    let response = match response {
        Ok(response) => response,
        Err(e) => {
            eprintln!("Recaptcha request failed: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("Recaptcha request failed: {}", e)).into_response();
        }
    };

    let response = if let Ok(res) = response.json::<ApiResponse>().await {
        res
    } else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "Recaptcha response is invalid.").into_response();
    };

    eprintln!("Recaptcha response: {:?}", response.success);
    if !response.success {
        return (StatusCode::BAD_REQUEST, "Recaptcha response is invalid.").into_response();
    }

    let message = request_token.as_bytes();
    let signing_key = SigningKey::from_bytes(&private_key);

    let signature = signing_key.sign(message);
    let signature = hex::encode(signature.to_bytes());

    let redirect_url = format!("{}?request-token={}&signature={}", redirect_url, request_token, signature);
    let mut header_map = HeaderMap::new();
    header_map.insert(HeaderName::from_static("location"), redirect_url.parse().unwrap());

    (
        StatusCode::SEE_OTHER,
        header_map,
        "Redirecting...",
    ).into_response()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv()?;

    // bind address
    let addr_string = env::var("LISTEN_ADDR").unwrap_or("".to_string());
    let addr = SocketAddr::from_str(&addr_string).unwrap_or(SocketAddr::from(([127, 0, 0, 1], 6770)));

    // define routes
    let app = Router::new()
        // top page
        .route("/", get(handler_root))

        .route("/submit", post(handler_submit))

        // assets directories
        .nest_service("/assets", ServeDir::new("assets"))

        // 404 page
        .fallback(handler_404)

        // add global headers
        .layer(axum::middleware::from_fn(add_global_headers));

    // run server
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    let server = axum::serve(listener, app);

    println!("Listening on http://{}", &addr);

    server.await?;

    Ok(())
}
