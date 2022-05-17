use serde::{Serialize, Deserialize};
use std::error::Error;
use uuid::Uuid;

use communication_tools::data_structures::{RegisterData,
                                           EmailConfirmationData,
                                           ServerResponse};
use input_validation::{email_validation::validate_email,
                       uuid_validation::validate_uuid};

use crate::connection::Connection;
use crate::database::Database;

//use crate::mailer::send_otp_mail;

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
        let data :RegisterData = connection.receive()?;

        // Validate data
        // TODO: verify hash and yubikey if possible
        if !validate_email(&data.email) {
            connection.send(&ServerResponse{
                message: String::from("Invalid email"),
                success: false,
            });
        } else {
            connection.send(&ServerResponse{
                message: String::from("Email sent"),
                success: true,
            });
        }

        // Email semantic validation -> send email
        // Generate UUID
        let uuid = Uuid::new_v4();
        let uuid_string = uuid.as_hyphenated().to_string();

        // Send email
        //sent_otp_email(&data.email, &uuid_string)?;

        // Wait for email token
        let data2 :EmailConfirmationData = connection.receive()?;

        if !validate_uuid(&data2.uuid) || uuid_string != data2.uuid {
            connection.send(&ServerResponse{
                message: String::from("Bad uuid"),
                success: false,
            });
        } else {
            connection.send(&ServerResponse{
                message: String::from("Account registered"),
                success: true,
            });
        }

        // Register in db
        Database::insert(&User{
            email: data.email,
            salt: data.salt,
            hash_password: data.hash_password,
            public_yubikey: data.yubikey,
            two_fa: false,
        });

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
    pub salt: Vec<u8>,
    pub hash_password: String,
    pub public_yubikey: Vec<u8>,
    pub two_fa: bool
}
