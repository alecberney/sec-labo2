use serde::{Serialize, Deserialize};
use std::error::Error;
use strum::IntoEnumIterator;
use strum_macros::{EnumString, EnumIter};

use communication_tools::data_structures::*;
use hashing_tools::hash_helpers::{hash_argon2, hashmac_sha256};

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

        println!("data sent");

        let return_message: ServerResponse = connection.receive()?;
        if !return_message.success {
            println!("{}", return_message.message);
            // TODO: return error
            return Err(Box::new(()));
        }

        // Ask for uuid token given in mail
        let email_uuid = ask_uuid();

        // Send email uuid confirmation value
        connection.send(&EmailConfirmationData {
            uuid: email_uuid,
        })?;

        let return_message2: ServerResponse = connection.receive()?;
        if !return_message2.success {
            println!("{}", return_message2.message);
            // TODO: return error
            return Err(Box::new(()));
        }

        Ok(())
    }

    fn authenticate(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        println!("<< Please authenticate yourself >>");

        let email = ask_email();
        let password_input = ask_password();

        // Send datas to server
        connection.send(&LoginData {
            email,
        })?;

        // Receive challenge
        let challenge: ChallengeData = connection.receive()?;

        // Creating the response with challenge
        let hash_password = hash_argon2(&password_input, &mut challenge.salt.as_array());
        let response;

        match hashmac_sha256(&challenge.challenge, &hash_password) {
            Ok(response_hash) => response = response_hash,
            Err(error) => {
                println!(error);
                return Err(Box::new(()));
            },
        }

        // Second factor authentification
        //let yubi_buffer = Yubi::sign(&secret)?;

        Ok(())
    }

    fn reset_password(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        // TODO
        // todo validate inputs and send to server
        Ok(())
    }
}