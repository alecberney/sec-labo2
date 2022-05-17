use rand::RngCore;
use argon2::{self, Config};
use sha2::Sha256;
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;

pub fn generate_random_16_bytes(bytes: &mut [u8; 16]) {
    let mut rng = rand::thread_rng();
    rng.fill_bytes(bytes);
}

// for salt perhaps: https://docs.rs/argon2/latest/argon2/
//https://docs.rs/rust-argon2/1.0.0/argon2/index.html
pub fn hash_argon2(input: &str, salt: &[u8; 16]) -> String {
    // TODO: remove unwrap and send Error
    argon2::hash_encoded(input.as_bytes(), salt, &Config::default()).unwrap()
}

pub fn hashmac_sha256(input: &[u8; 16], secret_key: &str) -> Result<[u8; 16], String> {
    // hashmac prend un hash déjà salé
    //https://docs.rs/hmac/0.12.1/hmac/index.html

    // faire dans tous les cas le hashmap même si user inconnu
    // le secret c'est le mdp hashé parce que clé dérivée // argon 2

    let mut mac;
    match HmacSha256::new_from_slice(secret_key.as_bytes()) {
        Ok(mac_result) => mac = mac_result,
        Err(_) => return Err(String::from("An error occured during mac generation")),
    };
    mac.update(input);

    // TODO
    Ok(mac.finalize().into_bytes()[..])
}