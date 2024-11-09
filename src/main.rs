use anyhow::{Context, Result};
use axum::{
    http::{StatusCode, HeaderMap},
    response::{Json as JsonResponse, IntoResponse}, 
    routing::{get, post}, 
    Router
};

use std::{
    //backtrace::Backtrace,
    net::SocketAddr, str, time::Instant
};
use std::panic::Location;

use tower_http::trace::TraceLayer;
use tracing::{error, info, span, Level}; //also error, warn, debug...
use tracing_subscriber;
use dotenv::dotenv;

use tracing_subscriber::EnvFilter;
use uuid::Uuid;

mod jwt;
mod utils;

#[tokio::main]
async fn main() {
    dotenv().ok();

    // Enable backtrace programmatically. This allows to get full stack on errors
    // env::set_var("RUST_BACKTRACE", "1");

    // Initialize the logging system with tracing-subscriber
    // Set up the subscriber with backtrace capture
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env()) // Dynamic filtering via RUST_LOG
        .with_writer(std::io::stdout)  // Output to stdout (or a file)
        .with_max_level(tracing::Level::INFO) // Set the logging level to INFO
        .init();

    // Build the app with routes
    let app = Router::new()
        .route("/makeMeAdmin", post(make_me_admin))
        .route("/makeMeUser", post(make_me_user))
        .route("/admin", get(test_admin))
        .route("/user", get(test_user))
        .route("/error", get(error_handler))
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

fn generate_request_id() -> String {
    Uuid::new_v4().to_string() // Generate a new request ID
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

    //Enter span context
    let request_id = generate_request_id();
    let span_val = span!(Level::INFO, "request", request_id = %request_id);
    let _enter = span_val.enter();

    let bearer_token = utils::get_bearer_token(&headers);
    let mut auth = None;
    let mut user = None;
    let mut user_valid = String::new();
    let mut auth_valid_r = String::new();
    if let Some(token) = bearer_token {
        let secret = utils::get_jwt_secret();
        auth = utils::get_role(token, &secret);
        user = utils::get_user(token, &secret);
    } 
    
    if let Some(auth_valid) = auth {
        auth_valid_r = auth_valid;
        user_valid = user.unwrap(); // must be set, since we got auth
        info!("Entering request: {} {} with authorization role {} for user {}", req_method, req_uri, &auth_valid_r, &user_valid);
    } else {
        info!("Entering request: {} {}", req_method, req_uri);
    }

    // Call the next handler in the stack
    let response = next.run(req).await;

    let duration = start_time.elapsed();

    if !auth_valid_r.is_empty() {
        info!("Exiting request: {} {} with status: {} (took {:?}) with authorization role {} for user {}", 
            req_method, //gives the location that investigation could be needed
            req_uri,
            response.status(), //important to determine if access was granted or request got wrong
            duration, //if it's too long, might have to investigate
            &auth_valid_r,
            &user_valid
        );
    } else {
        info!("Exiting request: {} {} with status: {} (took {:?})", 
            req_method, //gives the location that investigation could be needed
            req_uri,
            response.status(), //important to determine if access was granted or request got wrong
            duration //if it's too long, might have to investigate
        );
    }

    // Exits span context automatically when variable dropped at end of function

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

// Modify the handler to log and return 500 with a stack trace
async fn error_handler() -> Result<impl IntoResponse, (StatusCode, String)> {
    match do_something_that_fails().await {
        Ok(result) => Ok(JsonResponse(result)),
        Err(e) => {
            // Log the error and its stack trace
            error!("An error occurred at {}:{}\n{:?}", file!(), line!(), e);

            // Return a 500 Internal Server Error to the client
            Err((StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error".to_string()))
        }
    }
}

async fn do_something_that_fails() -> Result<String> {
    // Simulating an error that will generate a backtrace
    do_something_that_fails_2().await.context(log_method_location(Location::caller(), "do_something_that_fails"))
}

async fn do_something_that_fails_2() -> Result<String> {
    // Simulating an error that will generate a backtrace
    Err(anyhow::anyhow!("Failure in do_something_that_fails_2").context(log_method_location(Location::caller(), "do_something_that_fails_2")))?
}

fn log_method_location(location: &Location, method: &str) -> String {
    let file = location.file();
    let line = location.line();

    format!("at {} {}:{}", method, file, line)
}