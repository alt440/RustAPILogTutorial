use axum::http::HeaderMap;
use serde::Serialize;
use std::env;

use crate::jwt;

#[derive(Serialize)]
#[serde(untagged)]
pub enum JsonResponseToken<'a> { 
    // the 'a indicates the lifetime of a var. In this case, the variable message for Error will not outlive the object JsonResponseToken
    Success { token: String },
    Error { message: &'a str }
}

#[derive(Debug)]
pub enum Roles {
    Admin,
    User,
}

impl Roles {
    pub fn to_int(&self) -> u16 {
        match self {
            Roles::Admin => 9892,
            Roles::User => 3,
        }
    }
}

pub fn get_jwt_secret() -> String {
    //takes JWT_SECRET environment var or "secret" if var not found
    env::var("JWT_SECRET").unwrap_or("secret".to_string())
}

pub fn get_bearer_token(headers: &HeaderMap) -> Option<&str> {
    // Find the header value that contains our JWT token, and remove the start "Bearer "
    headers.get("Authorization").and_then(|h| h.to_str().ok()).map(|h| h.trim_start_matches("Bearer "))
}

pub fn get_user(token: &str, secret: &str) -> Option<String> {
    if let Ok(data) = jwt::validate_jwt(token, &secret) {
        return Some(data.claims.sub.clone());
    }
    return None;
}

pub fn get_role(token: &str, secret: &str) -> Option<String> {
    // verifies that validate_jwt does not return any errors (The Ok keyword validates a successful return), and assigns the non-erroneous return to data
    if let Ok(data) = jwt::validate_jwt(token, &secret) {
        // if role contains admin, access granted. Currently holds only 1 index
        // Don't know why I can't simply do a for role in &data.claims.roles... the index appears inexistant
        if let Some(first_role) = &data.claims.roles.get(0) {
            // for some reason, first_role extracted with " in prefix and suffix of string
            let role = *first_role;

            return Some(role.clone());
        }
    }
    return None;
}

pub fn is_admin(token: &str, secret: &str) -> bool{
    // verifies that validate_jwt does not return any errors (The Ok keyword validates a successful return), and assigns the non-erroneous return to data
    if let Ok(data) = jwt::validate_jwt(token, &secret) {
        // if role contains admin, access granted. Currently holds only 1 index
        // Don't know why I can't simply do a for role in &data.claims.roles... the index appears inexistant
        if let Some(first_role) = &data.claims.roles.get(0) {
            // for some reason, first_role extracted with " in prefix and suffix of string
            if (*first_role).contains(&Roles::Admin.to_int().to_string()) {
                return true;
            }
        }
    }
    return false;
}