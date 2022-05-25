use serde::{Serialize, Deserialize};
use std::error::Error;
use app_tools::communication::data::ChangeTwoFA;
use crate::connection::Connection;
use crate::authentication::User;
use crate::database::Database;

/// `Action` enum is used to perform logged operations:
/// -   Enable/Disable 2fa authentication
#[derive(Serialize, Deserialize, Debug)]
pub enum Action {
    Switch2FA,
    Logout
}

impl Action {
    pub fn perform(user: &mut User, connection: &mut Connection) -> Result<bool, Box<dyn Error>> {
        match connection.receive()? {
            Action::Switch2FA => Action::switch_2fa(user, connection),
            Action::Logout => Ok(false)
        }
    }

    fn switch_2fa(user: &mut User, connection: &mut Connection) -> Result<bool, Box<dyn Error>> {
        // Update 2 FA status in BD
        user.two_fa = !user.two_fa;
        Database::insert(&user)?;

        // Send new 2 FA status to client
        connection.send(&ChangeTwoFA {
            two_fa_status: user.two_fa
        })?;

        Ok(true)
    }
}