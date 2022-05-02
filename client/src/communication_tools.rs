use yubikey::piv::PublicKeyInfo;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RegisterData {
    pub email: String,
    pub hashed_password: Vec<u8>,
    pub salt: [u8; 16],
    pub yubikey: PublicKeyInfo,
}

pub struct LoginData {
    pub email: String,
    pub yubikey: String,
}

pub struct ResetPasswordData {
    pub email: String,
    pub yubikey: String,
}