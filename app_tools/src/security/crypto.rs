use rand::RngCore;
use argon2::{self, Config};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;

pub fn generate_random_16_bytes(bytes: &mut [u8; 16]) {
    let mut rng = rand::thread_rng();
    rng.fill_bytes(bytes);
}

/// We assume that the hash function will always works
pub fn hash_argon2(data: &str, salt: &[u8]) -> String {
    argon2::hash_encoded(data.as_bytes(), salt, &Config::default()).unwrap()
}

pub fn hash_sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()[..].to_vec()
}

/// Generate a MAC using a key and a data
/// # Arguments
/// * `data` - 16 bytes value usually random number
/// * `key` - Salted Hash from usually password
/// # Returns
/// * `Vec<u8>` - The mac generated
/// # Errors
/// * `String` - The error message
pub fn hashmac_sha256(data: &[u8; 16], key: &str) -> Result<Vec<u8>, String> {
    let mut mac;
    match HmacSha256::new_from_slice(key.as_bytes()) {
        Ok(mac_result) => mac = mac_result,
        Err(_) => return Err(String::from("An error occurred during mac generation")),
    };
    mac.update(data);
    Ok(mac.finalize().into_bytes()[..].to_vec())
}