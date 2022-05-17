use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RegisterData {
    pub email: String,
    pub hash_password: String,
    pub salt: Vec<u8>,
    pub yubikey: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EmailConfirmationData {
    pub uuid: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LoginData {
    pub email: String,
    pub yubikey: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ResetPasswordData {
    pub email: String,
    pub yubikey: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerResponse {
    pub message: String,
    pub success: bool,
}