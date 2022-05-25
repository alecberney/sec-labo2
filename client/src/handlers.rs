use read_input::prelude::*;
use communication_tools::messages::{INVALID_EMAIL, INVALID_PASSWORD, INVALID_PIN, INVALID_UUID};
use input_validation::{email_validation::validate_email,
                       password_validation::validate_password,
                       uuid_validation::validate_uuid,
                       pin_validation::validate_pin};

pub fn ask_email() -> String {
    loop {
        let email_input = input::<String>().msg("- Email: ").get();
        if validate_email(&email_input) {
            return email_input;
        }
        println!("{}", INVALID_EMAIL);
    }
}

pub fn ask_password() -> String {
    loop {
        let password_input = input::<String>().msg("- Password: ").get();
        if validate_password(&password_input) {
            return password_input;
        }
        println!("{}", INVALID_PASSWORD.to_string());
    }
}

pub fn ask_uuid() -> String {
    loop {
        let uuid_input = input::<String>().msg("- Email UUID: ").get();
        if validate_uuid(&uuid_input) {
            return uuid_input;
        }
        println!("{}", INVALID_UUID.to_string());
    }
}

pub fn ask_pin() -> String {
    loop {
        let pin_input = input::<String>().msg("- PIN: ").get();
        if validate_pin(&pin_input) {
            return pin_input;
        }
        println!("{}", INVALID_PIN.to_string());
    }
}