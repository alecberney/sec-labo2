use serde::{Serialize, Deserialize};

// Register
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

// Login
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
    pub response: Vec<u8>,
}

// Reset password
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ResetPasswordStep1Data {
    pub email: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ResetPasswordStep2Data {
    pub uuid: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ResetPasswordStep3Data {
    pub password: String,
}

// Other
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