use serde::{Serialize, Deserialize};
use crate::connection::Connection;
use std::error::Error;

use strum::IntoEnumIterator;
use strum_macros::{EnumString, EnumIter};

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
        Ok(()) // TODO
    }

    fn authenticate(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        Ok(()) // TODO
    }

    fn reset_password(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        Ok(()) // TODO
    }
}