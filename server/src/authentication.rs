use serde::{Serialize, Deserialize};
use std::error::Error;
use uuid::Uuid;

use communication_tools::data_structures::*;
use communication_tools::messages::*;
use hashing_tools::hash_helpers::*;
use input_validation::{email_validation::validate_email,
                       uuid_validation::validate_uuid,
                       password_validation::validate_password};

use crate::connection::Connection;
use crate::database::Database;
use crate::mailer::send_mail;

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
        let register_data:RegisterData = connection.receive()?;

        // Validate data
        // TODO: verify public yubikey if possible
        if !validate_email(&register_data.email) ||
            !validate_password(&register_data.password) {
            connection.send(&ServerResponse{
                message: String::from(INVALID_EMAIL),
                success: false,
            })?;
            return Err(INVALID_EMAIL.into());
        } else {
            connection.send(&ServerResponse{
                message: String::from(EMAIL_SENT),
                success: true,
            })?;
        }

        // Generate salt
        let mut salt: [u8; 16] = [0; 16];
        generate_random_16_bytes(&mut salt);

        // Hash password
        let hash_password = hash_argon2(&register_data.password, &mut salt);

        // Email semantic validation -> send email
        // Generate UUID
        // TODO: in a function
        let uuid = Uuid::new_v4();
        let uuid_string = uuid.as_hyphenated().to_string();

        // Send email
        let message = format!("Here is the validation token : {}", uuid_string);
        let subject = "Mail validation token";
        send_mail(&register_data.email, subject, &message)?;

        // Wait for email token
        let confirmation_data :EmailConfirmationData = connection.receive()?;

        // Send result message
        if !validate_uuid(&confirmation_data.uuid) || uuid_string != confirmation_data.uuid {
            connection.send(&ServerResponse{
                message: String::from(BAD_UUID),
                success: false,
            })?;
        } else {
            connection.send(&ServerResponse{
                message: String::from(ACCOUNT_REGISTERED),
                success: true,
            })?;
            return Err(BAD_UUID.into());
        }

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
        
        Ok(Some(user))

        // 2fa
        // https://docs.rs/ecdsa/0.13.4/ecdsa/index.html
        // https://docs.rs/yubikey/0.5.0/yubikey/piv/index.html
        // https://docs.yubico.com/software/yubikey/tools/ykman/Using_the_ykman_CLI.html#windows
    }

    fn reset_password(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        Ok(None) // TODO
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
