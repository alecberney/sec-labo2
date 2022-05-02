mod authentication;
mod connection;
mod action;
mod yubi;

use read_input::prelude::*;
use crate::authentication::Authenticate;
use crate::connection::Connection;
use crate::action::Action;

const SERVER_IP: &str = "127.0.0.1:8080";

fn main() {
    // Setup
    println!("--- Client ---");
    let mut connection = Connection::new(SERVER_IP);

    loop {
        // Authentication
        loop {
            Authenticate::display();
            let action = input::<Authenticate>().msg("Please select: ").get();

            match action.perform(&mut connection) {
                Ok(_) => break,
                Err(e) => eprintln!("Authentication failed with following errors: {}\n", e)
            };
        };

        println!("\n[[ Authentication success ]]\n");

        loop {
            Action::display();
            let action = input::<Action>().msg("Please select: ").get();

            match action.perform(&mut connection) {
                Ok(end) => if !end { break },
                Err(e) => eprintln!("Operation failed with following errors: {}\n", e)
            };
        }

        println!("\n[[ Logged Out ]]\n");
    }
}