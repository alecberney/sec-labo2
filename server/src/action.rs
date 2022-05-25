use serde::{Serialize, Deserialize};
use std::error::Error;
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
            Action::Switch2FA => Action::switch_2fa(user),
            Action::Logout => Ok(false)
        }
    }

    fn switch_2fa(user: &mut User) -> Result<bool, Box<dyn Error>> {
        user.two_fa = !user.two_fa;
        Database::insert(&user)?;
        // TODO inform client
        Ok(true) // TODO: perhaps change to user.two_fa

        /*
        let auth = Authenticate::authenticate(connection, true)?;
        if auth.is_some() {
            user.double_factor = !user.double_factor;
            Database::insert(&user)?;
            if user.double_factor == true{
                connection.send(&StatusCode::DoubleAuthActiveted)?;
            }else{
                connection.send(&StatusCode::DoubleAuthDeactiveted)?;
            }
        }
        Ok(true)
         */
    }
}