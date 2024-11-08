use axum::{
    http::{StatusCode, HeaderMap},
    response::{Json as JsonResponse, IntoResponse}, 
    routing::{get, post}, 
    Router
};
use std::net::SocketAddr;
use std::time::Instant;
use tower_http::trace::TraceLayer;
use tracing::info; //also error, warn, debug...
use tracing_subscriber;
use dotenv::dotenv;

mod jwt;
mod utils;

#[tokio::main]
async fn main() {
    dotenv().ok();
    // Initialize the logging system with tracing-subscriber
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO) // Set the logging level to INFO
        .init();

    // Build the app with routes
    let app = Router::new()
        .route("/makeMeAdmin", post(make_me_admin))
        .route("/makeMeUser", post(make_me_user))
        .route("/admin", get(test_user))
        .route("/user", get(test_admin))
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn(log_middleware)); // Adds HTTP request/response tracing

    // Define the socket address where the server will run
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    info!("Starting server at http://{}", addr);

    // Run the server
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

// A generic function that all handlers can pass through, logging entrance and exit
async fn log_middleware<B>(
    req: axum::http::Request<B>,
    next: axum::middleware::Next<B>,
) -> impl IntoResponse {
    let start_time = Instant::now();
    let req_method = req.method().clone();
    let req_uri = req.uri().clone();
    
    let headers: HeaderMap = req.headers().clone();
    
    let bearer_token = utils::get_bearer_token(&headers);
    let mut auth = None;
    let mut auth_valid_r = String::new();
    if let Some(token) = bearer_token {
        let secret = utils::get_jwt_secret();
        auth = utils::get_role(token, &secret);
    } 
    
    if let Some(auth_valid) = auth {
        auth_valid_r = auth_valid;
        info!("Entering request: {} {} with authorization role {} ", req_method, req_uri, &auth_valid_r);
    } else {
        info!("Entering request: {} {}", req_method, req_uri);
    }

    // Call the next handler in the stack
    let response = next.run(req).await;

    let duration = start_time.elapsed();

    if !auth_valid_r.is_empty() {
        info!("Exiting request: {} {} with status: {} (took {:?}) with authorization role {}", 
            req_method, //gives the location that investigation could be needed
            req_uri,
            response.status(), //important to determine if access was granted or request got wrong
            duration, //if it's too long, might have to investigate
            &auth_valid_r
        );
    } else {
        info!("Exiting request: {} {} with status: {} (took {:?})", 
            req_method, //gives the location that investigation could be needed
            req_uri,
            response.status(), //important to determine if access was granted or request got wrong
            duration //if it's too long, might have to investigate
        );
    }

    response
}

async fn test_user(headers: HeaderMap) -> impl IntoResponse {
    let bearer_token = utils::get_bearer_token(&headers);

    if let Some(token) = bearer_token {
        let secret = utils::get_jwt_secret();
        if let Ok(_) = jwt::validate_jwt(token, &secret) {
            return (StatusCode::OK, "User access granted!").into_response();
        }
    }
    (StatusCode::FORBIDDEN, "Forbidden").into_response()
}

async fn test_admin(headers: HeaderMap) -> impl IntoResponse {
    let bearer_token = utils::get_bearer_token(&headers);

    if let Some(token) = bearer_token {
        //takes JWT_SECRET environment var or "secret" if var not found
        let secret = utils::get_jwt_secret();

        // verifies that validate_jwt does not return any errors (The Ok keyword validates a successful return), and assigns the non-erroneous return to data
        if utils::is_admin(token, &secret) {
            return (StatusCode::OK, "Admin access granted!").into_response();
        }
    }
    (StatusCode::FORBIDDEN, "Forbidden").into_response()
}

async fn make_me_admin() -> impl IntoResponse {
    let secret = utils::get_jwt_secret();
    //creates JWT token with username and role admin with secret
    let token = jwt::create_jwt("adminMaster999", vec![utils::Roles::Admin.to_int().to_string()], &secret);

    let response = utils::JsonResponseToken::Success {
        token: token
    };
    (StatusCode::OK, JsonResponse(response))
}

async fn make_me_user() -> impl IntoResponse {
    let secret = utils::get_jwt_secret();
    //creates JWT token with username and role admin with secret
    let token = jwt::create_jwt("theDummyUser", vec![utils::Roles::User.to_int().to_string()], &secret);

    let response = utils::JsonResponseToken::Success {
        token: token
    };
    (StatusCode::OK, JsonResponse(response))
}