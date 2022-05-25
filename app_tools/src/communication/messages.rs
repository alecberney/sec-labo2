// Errors
pub static INVALID_EMAIL: &str = "Invalid email";
pub static INVALID_PASSWORD: &str = "Invalid password: must contain at least 1 upper case, \
1 lower case, 1 number and has a length of min 8";
pub static INVALID_PUBLIC_KEY: &str = "Invalid public key";
pub static INVALID_UUID: &str = "Invalid uuid: must have format 00000000-0000-0000-0000-000000000000";
pub static INVALID_PIN: &str = "Invalid pin: must contains at least 6 and maximum 8 characters";
pub static BAD_UUID: &str = "Bad uuid";
pub static WRONG_KEY: &str = "Wrong yubikey";
pub static AUTH_FAIL: &str = "Invalid user and password combination";
pub static ACCOUNT_EXISTING: &str = "An account with same email already exists";

// Success
pub static EMAIL_SENT: &str = "Email sent";
pub static VALID_EMAIL: &str = "Email is valid and account exists";
pub static ACCOUNT_REGISTERED: &str = "Account registered";
pub static AUTH_SUCCESS: &str = "Authentification success";
pub static AUTH_TWO_FA: &str = "First part of authentification success";
pub static CORRECT_UUID: &str = "Correct UUID from email";