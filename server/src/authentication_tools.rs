use uuid::Uuid;
use std::error::Error;
use p256::ecdsa::VerifyingKey;

use hashing_tools::hash_helpers::*;
use communication_tools::data_structures::ServerResponse;
use input_validation::uuid_validation::validate_uuid;
use communication_tools::messages::BAD_UUID;


use crate::connection::Connection;
use crate::mailer::send_mail;

pub fn hash_password(password: &str) -> ([u8; 16], String) {
    let mut salt: [u8; 16] = [0; 16];
    generate_random_16_bytes(&mut salt);
    let hash_password = hash_argon2(password, &mut salt);
    (salt, hash_password)
}

pub fn generate_string_uuid() -> String {
    let uuid = Uuid::new_v4();
    uuid.as_hyphenated().to_string()
}

pub fn send_token_email(dst: &str, subject: &str, token_message: &str) -> Result<String, String> {
    let uuid = generate_string_uuid();
    let message = format!("{} : {}", token_message, uuid);
    send_mail(dst, subject, &message)?;
    Ok(uuid)
}

pub fn validate_email_uuid(connection: &mut Connection,
                           uuid_to_match: &str,
                           uuid_to_test: &str,
                           success_message: &str) -> Result<(), Box<dyn Error>> {
    if !validate_uuid(uuid_to_test) || uuid_to_test != uuid_to_match {
        connection.send(&ServerResponse{
            message: String::from(BAD_UUID),
            success: false,
        })?;
        return Err(BAD_UUID.into());
    } else {
        connection.send(&ServerResponse{
            message: String::from(success_message),
            success: true,
        })?;
    }
    Ok(())
}

pub fn validate_public_key(public_key: &Vec<u8>) -> bool {
    return match VerifyingKey::from_sec1_bytes(public_key) {
        Ok(_) => true,
        Err(_) => false
    }
}