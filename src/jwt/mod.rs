use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, TokenData};

// you have to include the file from main directory (there is also an extra 'models' in this because of the mod it is in)
// can only be used if the mod models is made public in models.rs
//use crate::dbInteractions::models::models::Claims;

//Claims is in the submodule, with accessible structs. Thus, the models are accessible from here
//Since it isn't prefixed with pub, the visibility of models stops here
//You can go more hardcore with this, limiting structures and functions to specific paths and the crate itself
//check: https://doc.rust-lang.org/rust-by-example/mod/visibility.html
//Essentially, use pub(crate) for availability in crate, or pub(in crate::my_mod) for availability only in a specific mod
mod jwt_struct;
//If there was a sub-module that we wanted to make public we would do:
//pub mod db;

pub fn create_jwt(username: &str, roles: Vec<String>, secret: &str) -> String {
    let claims = jwt_struct::Claims {
        sub: username.to_owned(),
        roles,
        exp: 10000000000, // Set expiration
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref())).unwrap()
}

pub fn validate_jwt(token: &str, secret: &str) -> Result<TokenData<jwt_struct::Claims>, jsonwebtoken::errors::Error> {
    decode::<jwt_struct::Claims>(token, &DecodingKey::from_secret(secret.as_ref()), &Validation::default())
}