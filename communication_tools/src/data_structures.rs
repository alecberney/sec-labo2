use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RegisterData {
    pub email: String,
    pub password: String,
    pub public_yubikey: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EmailConfirmationData {
    pub uuid: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LoginData {
    pub email: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChallengeData {
    pub challenge: [u8; 16],
    pub salt: [u8; 16],
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ResponseData {
    pub response: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SecondFactorData {
    pub challenge: String,
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