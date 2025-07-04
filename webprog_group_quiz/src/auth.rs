use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use actix_session::Session;
use actix_web::HttpResponse;


const SALT: &str = "bugtrack2025";


#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,  
    pub exp: usize,   
    pub role: String,   
}

// Password hashing remains the same
pub fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(SALT.as_bytes());
    hasher.update(password.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn verify_password(input_password: &str, expected_hash: &str) -> bool {
    hash_password(input_password) == expected_hash
}


// Store user login data in session
pub fn store_user_session(session: &Session, username: &str, role: &str) -> Result<(), actix_web::Error> {
    session.insert("username", username)?;
    session.insert("role", role)?;
    Ok(())
}