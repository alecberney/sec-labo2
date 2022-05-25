use serde::{Serialize, Deserialize};
use std::error::Error;

use app_tools::security::crypto::{generate_random_16_bytes, hashmac_sha256};
use app_tools::communication::data::*;
use app_tools::communication::messages::*;
use app_tools::input_validation::{email::validate_email, password::validate_password};

use crate::connection::Connection;
use crate::database::Database;
use crate::authentication_tools::{hash_password,
                                  send_token_email,
                                  validate_email_uuid,
                                  validate_public_key,
                                  verify_challenge_yubikey};

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
        let register_data :RegisterData = connection.receive()?;
        let mut error_message = "";

        if !validate_email(&register_data.email) {
            error_message = INVALID_EMAIL;
        }

        if !validate_password(&register_data.password) {
            error_message = INVALID_PASSWORD;
        }

        if !validate_public_key(&register_data.public_yubikey) {
            error_message = INVALID_PUBLIC_KEY;
        }

        // Verify if account exists
        if Database::get(&register_data.email)?.is_some() {
            error_message = ACCOUNT_EXISTING;
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
        let confirmation_data :UUIDData = connection.receive()?;

        // Send result message
        validate_email_uuid(connection,
                            &uuid,
                            &confirmation_data.uuid,
                            ACCOUNT_REGISTERED)?;

        // Hash password for DB
        let (salt, hash_password) = hash_password(&register_data.password);

        // Register in db
        // 2 FA is by default as false
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
        let email_data :EmailData = connection.receive()?;

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
        // because we always want the same time of response
        if validate_email(&email_data.email) {
            match Database::get(&email_data.email)? {
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
        connection.send(&ChallengeWithSaltData {
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
            connection.send(&ServerResponseTwoFA{
                message: AUTH_FAIL.to_string(),
                success: false,
                two_fa: false
            })?;
            return Ok(None);
        }

        // Send if auth is success or still need a 2FA
        if !user.two_fa {
            connection.send(&ServerResponseTwoFA{
                message: AUTH_SUCCESS.to_string(),
                success: true,
                two_fa: false
            })?;
            return Ok(Some(user));
        } else {
            connection.send(&ServerResponseTwoFA{
                message: AUTH_TWO_FA.to_string(),
                success: true,
                two_fa: true
            })?;
        }

        // Second factor authentification
        // We don't send a new challenge because we use same challenge than before
        let two_fa_response :ResponseData = connection.receive()?;
        if verify_challenge_yubikey(&user.public_yubikey, &challenge, &two_fa_response.response)? {
            connection.send(&ServerResponse {
                message: AUTH_SUCCESS.to_string(),
                success: true,
            })?;
            Ok(Some(user))
        } else {
            connection.send(&ServerResponse {
                message: WRONG_KEY.to_string(),
                success: false,
            })?;
            Ok(None)
        }
    }

    fn reset_password(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        // Validate email
        let email_data:EmailData = connection.receive()?;
        let mut valid_email = false;
        let mut reset_user = None;

        if validate_email(&email_data.email) {
            reset_user = Database::get(&email_data.email)?;
            if reset_user.is_some() {
                valid_email = true;
            }
        }

        let mut challenge: [u8; 16];

        if valid_email {
            // Verify that is the good user with 2FA
            // Creating challenge
            challenge = [0; 16];
            generate_random_16_bytes(&mut challenge);

            // Confirm email validation
            connection.send(&ServerResponse{
                message: String::from(VALID_EMAIL),
                success: true,
            })?;

            // Sending challenge
            connection.send(&ChallengeData {
                challenge,
            })?;
        } else {
            connection.send(&ServerResponse{
                message: String::from(INVALID_EMAIL),
                success: false,
            })?;
            return Err(INVALID_EMAIL.into());
        }

        // Receive response
        let response_data: ResponseData = connection.receive()?;
        if verify_challenge_yubikey(&reset_user.as_ref().unwrap().public_yubikey, &challenge, &response_data.response)? {
            connection.send(&ServerResponse{
                message: String::from(EMAIL_SENT),
                success: true,
            })?;
        } else {
            connection.send(&ServerResponse{
                message: String::from(WRONG_KEY),
                success: false,
            })?;
            return Err(WRONG_KEY.into());
        }

        // Send reset email
        let uuid = send_token_email(&email_data.email,
                                    "Reset password mail",
                                    "Here is the reset password token : ")?;

        let uuid_data :UUIDData = connection.receive()?;

        // Send result message
        validate_email_uuid(connection,
                            &uuid,
                            &uuid_data.uuid,
                            CORRECT_UUID)?;

        let password_data :PasswordData = connection.receive()?;

        if !validate_password(&password_data.password) {
            connection.send(&ServerResponse{
                message: String::from(INVALID_PASSWORD),
                success: false,
            })?;
            Err(INVALID_PASSWORD.into())
        } else {
            // Update in db
            let (salt, hash_password) = hash_password(&password_data.password);
            match reset_user {
                Some(mut user_db) => {
                    user_db.hash_password = hash_password;
                    user_db.salt = salt;
                    Database::insert(&user_db)?;
                    Ok(Some(user_db))
                },
                None => return Err(INVALID_EMAIL.into()),
            }
        }
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
