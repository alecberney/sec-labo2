use serde::{Serialize, Deserialize};
use std::error::Error;
use uuid::Uuid;
use input_validation::{email_validation::validate_email,
                       password_validation::validate_password,
                       uuid_validation::validate_uuid};

use crate::connection::Connection;

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
        connection.receive()?;
        // todo add communication tools library

        // Validate datas

        // Send ok message

        // Email semantic validation -> send email
        // Generate UUID
        let uuid = Uuid::new_v4();

        // Send email
        sent_otp_email(&email, &uuid)?;

        // Wait for email token
        connection.receive()?;

        // Register in db
        Ok(None)
    }

    fn reset_password(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        Ok(None) // TODO
    }

    fn authenticate(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        Ok(None) // TODO

        // 2fa
        // https://docs.rs/ecdsa/0.13.4/ecdsa/index.html
        // https://docs.rs/yubikey/0.5.0/yubikey/piv/index.html
        // https://docs.yubico.com/software/yubikey/tools/ykman/Using_the_ykman_CLI.html#windows
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct User {
    pub email: String,
    pub salt: String,
    pub hash_password: String,
    pub public_yubikey: String,
    pub two_fa: bool
    // TODO
}
