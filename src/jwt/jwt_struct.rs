use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub roles: Vec<String>,
    pub exp: usize,
}