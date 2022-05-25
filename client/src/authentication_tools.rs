use std::error::Error;
use app_tools::security::crypto::hash_sha256;
use app_tools::communication::data::ServerResponse;
use crate::yubi::Yubi;
use crate::connection::Connection;

pub fn generate_yubikey_signature(challenge: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(Yubi::sign(&hash_sha256(challenge))?.to_vec())
}

// TODO
pub fn handle_server_response(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
    let return_message: ServerResponse = connection.receive()?;
    if !return_message.success {
        return Err(format!("{}", return_message.message).into());
    }
    Ok(())
}