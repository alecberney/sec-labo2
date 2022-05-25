use rand::RngCore;
use argon2::{self, Config};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;

pub fn generate_random_16_bytes(bytes: &mut [u8; 16]) {
    let mut rng = rand::thread_rng();
    rng.fill_bytes(bytes);
}

// for salt perhaps: https://docs.rs/argon2/latest/argon2/
//https://docs.rs/rust-argon2/1.0.0/argon2/index.html
pub fn hash_argon2(input: &str, salt: &[u8]) -> String {
    argon2::hash_encoded(input.as_bytes(), salt, &Config::default()).unwrap()
}

pub fn hash_sha256(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize()[..].to_vec()
}

/// In our program:
/// # Arguments
/// * `input` - Random 16 bytes number
/// * `secret_key` - Salted Hash from password
/// # Returns
/// * `Vec<u8>` -
/// # Errors
/// * `String` -
pub fn hashmac_sha256(input: &[u8; 16], secret_key: &str) -> Result<Vec<u8>, String> {
    let mut mac;
    match HmacSha256::new_from_slice(secret_key.as_bytes()) {
        Ok(mac_result) => mac = mac_result,
        Err(_) => return Err(String::from("An error occurred during mac generation")),
    };
    mac.update(input);
    Ok(mac.finalize().into_bytes()[..].to_vec())
}