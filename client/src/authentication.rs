use serde::{Serialize, Deserialize};
use std::error::Error;
use strum::IntoEnumIterator;
use strum_macros::{EnumString, EnumIter};

use communication_tools::data_structures::*;
use hashing_tools::hash_helpers::{hash_argon2, hash_sha256, hashmac_sha256};

use crate::connection::Connection;
use crate::handlers::*;
use crate::yubi::Yubi;

/// `Authenticate` enum is used to perform:
/// -   User
/// -   Registration
/// -   Password Reset
#[derive(Serialize, Deserialize, Debug, EnumString, EnumIter)]
pub enum Authenticate {
    #[strum(serialize = "Authenticate", serialize = "1")]
    Authenticate,
    #[strum(serialize = "Register", serialize = "2")]
    Register,
    #[strum(serialize = "Reset password", serialize = "3")]
    Reset,
    #[strum(serialize = "Exit", serialize = "4")]
    Exit
}

impl Authenticate {
    pub fn display() {
        let mut actions = Authenticate::iter();
        for i in 1..=actions.len() { println!("{}.\t{:?}", i, actions.next().unwrap()); }
    }

    pub fn perform(&self, connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        connection.send(self)?;

        match self {
            Authenticate::Authenticate => Authenticate::authenticate(connection),
            Authenticate::Register => Authenticate::register(connection),
            Authenticate::Reset => Authenticate::reset_password(connection),
            Authenticate::Exit => {
                println!("Exiting..."); std::process::exit(0);
            }
        }
    }

    fn register(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        println!("<< Please register yourself >>");

        let email = ask_email();
        let password_input = ask_password();
        let public_yubikey = Yubi::generate_keys()?;

        // Send datas to server
        connection.send(&RegisterData {
            email,
            password: password_input,
            public_yubikey,
        })?;

        // Handle server response
        let return_message: ServerResponse = connection.receive()?;
        if !return_message.success {
            return Err(format!("{}", return_message.message).into());
        }

        // Send email uuid confirmation value
        connection.send(&EmailConfirmationData {
            uuid: ask_uuid(),
        })?;

        // Handle server response
        let return_message2: ServerResponse = connection.receive()?;
        if !return_message2.success {
            return Err(format!("{}", return_message2.message).into());
        }

        Ok(())
    }

    fn authenticate(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        println!("<< Please authenticate yourself >>");

        // Send datas to server
        connection.send(&LoginData {
            email: ask_email(),
        })?;

        let password_input = ask_password();

        // Receive challenge
        let mut challenge: ChallengeData = connection.receive()?;

        // Creating the response with challenge
        let hash_password = hash_argon2(&password_input, &mut challenge.salt);
        match hashmac_sha256(&challenge.challenge, &hash_password) {
            Ok(response_hash) => {
                // Send response datas to server
                connection.send(&ResponseData {
                    response: response_hash,
                })?;
            },
            Err(error) => {
                return Err(error.into());
            },
        }

        // Handle server response
        let serveur_response :ServerResponseTwoFA = connection.receive()?;
        if !serveur_response.success {
            return Err(format!("{}", serveur_response.message).into());
        } else if !serveur_response.two_fa {
            return Ok(());
        }

        // Second factor authentification
        // We use same challenge than before (for the hmac part)
        let challenge_hashed = hash_sha256(&challenge.challenge);
        let yubi_buffer = Yubi::sign(&challenge_hashed)?;

        connection.send(&SecondFactorData {
            response: yubi_buffer.to_vec()
        })?;

        let challenge_result :ServerResponse = connection.receive()?;
        if !challenge_result.success {
            return Err(format!("{}", challenge_result.message).into());
        }

        Ok(())
    }

    fn reset_password(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        println!("<< Reset password >>");

        // TODO: faire auth yubikey via challenge response après avoir valider l'email

        // Send email to server
        connection.send(&ResetPasswordStep1Data {
            email: ask_email(),
        })?;

        let return_message: ServerResponse = connection.receive()?;
        if !return_message.success {
            return Err(format!("{}", return_message.message).into());
        }

        // Send email with uuid confirmation value
        connection.send(&ResetPasswordStep2Data {
            uuid: ask_uuid(),
        })?;

        // Handle server response
        let return_message2: ServerResponse = connection.receive()?;
        if !return_message2.success {
            return Err(format!("{}", return_message2.message).into());
        }

        // Send new password
        connection.send(&ResetPasswordStep3Data {
            password: ask_password(),
        })?;

        Ok(())
    }
}