use serde::{Serialize, Deserialize};
use std::error::Error;

use communication_tools::data_structures::*;
use communication_tools::messages::*;
use hashing_tools::hash_helpers::*;
use input_validation::{email_validation::validate_email, password_validation::validate_password};

use crate::connection::Connection;
use crate::database::Database;
use crate::authentication_tools::{hash_password, send_token_email, validate_email_uuid};

/// `Authenticate` enum is used to perform:
/// -   Authentication
/// -   Registration
/// -   Password Reset
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum Authenticate {
    Authenticate,
    Register,
    Reset,
    Exit
}

impl Authenticate {
    pub fn perform(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        match connection.receive()? {
            Authenticate::Authenticate => Authenticate::authenticate(connection),
            Authenticate::Register => Authenticate::register(connection),
            Authenticate::Reset => Authenticate::reset_password(connection),
            Authenticate::Exit => Err("Client disconnected")?
        }
    }

    fn register(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        // Validate data
        let register_data:RegisterData = connection.receive()?;
        let mut error_message = "";

        // TODO: verify public yubikey if possible
        if !validate_email(&register_data.email) {
            error_message = INVALID_EMAIL;
        }

        if !validate_password(&register_data.password) {
            error_message = INVALID_PASSWORD;
        }

        if error_message != "" {
            connection.send(&ServerResponse{
                message: String::from(error_message),
                success: false,
            })?;
            return Err(error_message.into());
        } else {
            connection.send(&ServerResponse{
                message: String::from(EMAIL_SENT),
                success: true,
            })?;
        }

        // Send email for semantic validation
        let uuid = send_token_email(&register_data.email,
                              "Mail validation token",
                              "Here is the validation token")?;

        // Wait for email token
        let confirmation_data :EmailConfirmationData = connection.receive()?;

        // Send result message
        validate_email_uuid(connection,
                            &uuid,
                            &confirmation_data.uuid,
                            ACCOUNT_REGISTERED)?;

        // Hash password for DB
        let (salt, hash_password) = hash_password(&register_data.password);

        // Register in db
        let user = User {
            email: register_data.email,
            salt,
            hash_password,
            public_yubikey: register_data.public_yubikey,
            two_fa: false,
        };
        Database::insert(&user)?;

        Ok(Some(user))
    }

    fn authenticate(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        let login_data :LoginData = connection.receive()?;

        // Default user
        let mut user = User {
            email: "default@default.default".to_string(),
            salt: [0; 16],
            hash_password: "default".to_string(),
            public_yubikey: vec![],
            two_fa: false
        };
        let mut user_salt: [u8; 16] = [0; 16];
        let mut valid_user = false;

        // We always do all the process of checking even if there is no user
        // because we always want the same time of reponse

        if validate_email(&login_data.email) {
            match Database::get(&login_data.email)? {
                Some(user_found) => {
                    valid_user = true;
                    user_salt = user_found.salt;
                    user = user_found;
                },
                None => valid_user = false,
            }
        }

        // Creating challenge
        let mut challenge: [u8; 16] = [0; 16];
        generate_random_16_bytes(&mut challenge);

        // Sending challenge
        connection.send(&ChallengeData{
            challenge,
            salt: user_salt,
        })?;

        // Creating the answer to challenge
        let response;
        match hashmac_sha256(&challenge, &user.hash_password) {
            Ok(response_hash) => response = response_hash,
            Err(error) => {
                return Err(format!("{}", error).into());
            },
        }

        let response_data :ResponseData = connection.receive()?;

        if response_data.response != response || !valid_user {
            connection.send(&ServerResponse{
                message: AUTH_FAIL.to_string(),
                success: false
            })?;
            return Ok(None)
        }

        // TODO 2fa
        
        Ok(Some(user))

        // 2fa
        // https://docs.rs/ecdsa/0.13.4/ecdsa/index.html
        // https://docs.rs/yubikey/0.5.0/yubikey/piv/index.html
        // https://docs.yubico.com/software/yubikey/tools/ykman/Using_the_ykman_CLI.html#windows
    }

    fn reset_password(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        // Validate email
        let reset_step1_data :ResetPasswordStep1Data = connection.receive()?;
        let mut valid_email = false;
        let mut reset_user = None;

        if validate_email(&reset_step1_data.email) {
            reset_user = Database::get(&reset_step1_data.email)?;
            if let Some(_) = reset_user {
                valid_email = true;
            }
        }

        if valid_email {
            connection.send(&ServerResponse{
                message: String::from(EMAIL_SENT),
                success: true,
            })?;
        } else {
            connection.send(&ServerResponse{
                message: String::from(INVALID_EMAIL),
                success: false,
            })?;
            return Err(INVALID_EMAIL.into());
        }

        // Send reset email
        let uuid = send_token_email(&reset_step1_data.email,
                                    "Reset password mail",
                                    "Here is the reset password token : ")?;

        let reset_step2_data :ResetPasswordStep2Data = connection.receive()?;

        // Send result message
        validate_email_uuid(connection,
                            &uuid,
                            &reset_step2_data.uuid,
                            CORRECT_UUID)?;

        let reset_step3_data :ResetPasswordStep3Data = connection.receive()?;

        if !validate_password(&reset_step3_data.password) {
            connection.send(&ServerResponse{
                message: String::from(INVALID_PASSWORD),
                success: false,
            })?;
        } else {
            // Update in db
            let (salt, hash_password) = hash_password(&reset_step3_data.password);
            match reset_user {
                Some(mut user_db) => {
                    user_db.hash_password = hash_password;
                    user_db.salt = salt;
                    Database::insert(&user_db)?;
                },
                None => return Err(INVALID_EMAIL.into()),
            }
        }

        Ok(None)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct User {
    pub email: String,
    pub salt: [u8; 16],
    pub hash_password: String,
    pub public_yubikey: Vec<u8>,
    pub two_fa: bool
}
