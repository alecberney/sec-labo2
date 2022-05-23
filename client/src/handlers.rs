use read_input::prelude::*;
use communication_tools::messages::*;
use input_validation::{email_validation::validate_email,
                       password_validation::validate_password,
                       uuid_validation::validate_uuid};

pub fn ask_email() -> String {
    loop {
        let email_input = input::<String>().msg("- Email: ").get();
        if validate_email(&email_input) {
            return email_input;
        }
        println!(INVALID_EMAIL);
    }
}

pub fn ask_password() -> String {
    loop {
        let password_input = input::<String>().msg("- Password: ").get();
        if validate_password(&password_input) {
            return password_input;
        }
        println!(INVALID_PASSWORD);
    }
}

pub fn ask_uuid() -> String {
    loop {
        let uuid_input = input::<String>().msg("- Email UUID: ").get();
        if validate_uuid(&uuid_input) {
            return uuid_input;
        }
        println!(INVALID_UUID);
    }
}