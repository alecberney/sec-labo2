use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RegisterData {
    pub email: String,
    pub hash_password: String,
    pub salt: [u8; 16],
    pub yubikey: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LoginData {
    pub email: String,
    pub yubikey: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ResetPasswordData {
    pub email: String,
    pub yubikey: String,
}