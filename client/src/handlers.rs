use read_input::prelude::*;
use input_validation::{validate_email, validate_password};

pub fn ask_email() -> String {
    loop {
        let email_input = input::<String>().msg("- Email: ").get();
        if validate_email(&email_input) {
            return email_input;
        }
    }
}

pub fn ask_password() -> String {
    loop {
        let password_input = input::<String>().msg("- Password: ").get();
        if validate_password(&password_input) {
            return password_input;
        }
    }
}