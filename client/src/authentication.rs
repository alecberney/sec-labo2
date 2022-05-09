use serde::{Serialize, Deserialize};
use std::error::Error;
use strum::IntoEnumIterator;
use strum_macros::{EnumString, EnumIter};
use argon2::{self, Config};
use rand::RngCore;
//use sha2::Sha256;
//use hmac::{Hmac, Mac};

use crate::connection::Connection;
use crate::communication_tools::{RegisterData};
use crate::handlers::*;
use crate::yubi::Yubi;

//type HmacSha256 = Hmac<Sha256>;

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

        // Generate salt of 16 bytes / 128 bits
        let mut rng = rand::thread_rng();
        let mut salt: [u8; 16] = [0; 16];
        rng.fill_bytes(&mut salt);

        // for salt perhaps: https://docs.rs/argon2/latest/argon2/

        // Hash password
        //https://docs.rs/rust-argon2/1.0.0/argon2/index.html
        let password = password_input.as_bytes();
        let config = Config::default();
        let hash_password = argon2::hash_encoded(password, &salt, &config).unwrap();
        //let matches = argon2::verify_encoded(&hash, password).unwrap();

        let yubikey = Yubi::generate_keys()?;

        // Send datas to server
        connection.send(&RegisterData {
            email,
            hash_password,
            salt,
            yubikey,
        })?;

        // Ask for uuid token given in mail
        ask_uuid();

        Ok(())
    }

    fn authenticate(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        // TODO
        // todo validate inputs and send to server

        // hashmac prend un hash déjà salé
        //https://docs.rs/hmac/0.12.1/hmac/index.html

        // faire dans tous les cas le hashmap même si user inconnu
        // le secret c'est le mdp hashé parce que clé dérivée // argon 2
        //let mut mac = HmacSha256::new_from_slice(b"my secret and secure key")?;


        //mac.update(b"input message"); // challenge
        //let hashed_password = mac.finalize().into_bytes();
        Ok(())
    }

    fn reset_password(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        // TODO
        // todo validate inputs and send to server
        Ok(())
    }
}