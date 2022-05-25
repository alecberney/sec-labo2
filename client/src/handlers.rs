use read_input::prelude::*;
use app_tools::communication::messages::{INVALID_EMAIL,
                                         INVALID_PASSWORD,
                                         INVALID_PIN,
                                         INVALID_UUID};
use app_tools::input_validation::{email::validate_email,
                       password::validate_password,
                       uuid::validate_uuid,
                       pin::validate_pin};

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

