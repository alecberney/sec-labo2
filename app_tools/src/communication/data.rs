use serde::{Serialize, Deserialize};

// Register
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RegisterData {
    pub email: String,
    pub password: String,
    pub public_yubikey: Vec<u8>,
}

// Challenge - Response data
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChallengeWithSaltData {
    pub challenge: [u8; 16],
    pub salt: [u8; 16],
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChallengeData {
    pub challenge: [u8; 16],
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ResponseData {
    pub response: Vec<u8>,
}

// Specific datas used in different actions
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EmailData {
    pub email: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PasswordData {
    pub password: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UUIDData {
    pub uuid: String,
}

// Server responses
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerResponse {
    pub message: String,
    pub success: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerResponseTwoFA {
    pub message: String,
    pub success: bool,
    pub two_fa: bool,
}

// Two factor activation / de-activation
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChangeTwoFA {
    pub two_fa_status: bool,
}