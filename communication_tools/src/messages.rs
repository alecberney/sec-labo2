// Errors
#[warn(dead_code)]
pub static INVALID_EMAIL: &str = "Invalid email";
#[warn(dead_code)]
pub static INVALID_PASSWORD: &str = "Invalid password: must contain at least 1 upper case, \
1 lower case, 1 number and has a length of min 8";
#[warn(dead_code)]
pub static INVALID_PUBLIC_KEY: &str = "Invalid public key";
#[warn(dead_code)]
pub static INVALID_UUID: &str = "Invalid uuid: must have format 00000000-0000-0000-0000-000000000000";
#[warn(dead_code)]
pub static INVALID_PIN: &str = "Invalid pin: must contains at least 6 and maximum 8 characters";
#[warn(dead_code)]
pub static BAD_UUID: &str = "Bad uuid";
#[warn(dead_code)]
pub static AUTH_FAIL: &str = "Invalid user and password combination";

// Success
#[warn(dead_code)]
pub static EMAIL_SENT: &str = "Email sent";
#[warn(dead_code)]
pub static ACCOUNT_REGISTERED: &str = "Account registered";
#[warn(dead_code)]
pub static AUTH_SUCCESS: &str = "Authentification success";
#[warn(dead_code)]
pub static AUTH_TWO_FA: &str = "First part of authentification success";
#[warn(dead_code)]
pub static CORRECT_UUID: &str = "Correct UUID from email";