use std::net::{TcpStream};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::error::Error;

pub struct Connection {
    stream: TcpStream
}

impl Connection {
    pub fn new(stream: TcpStream) -> Connection { Connection{stream} }

    pub fn send<T>(&mut self, o: &T) -> Result<(), Box<dyn Error>> where T: Serialize {
        Ok(bincode::serialize_into(&self.stream, &o)?)
    }

    pub fn receive<T>(&mut self) -> Result<T, Box<dyn Error>> where T: DeserializeOwned {
        Ok(bincode::deserialize_from(&self.stream)?)
    }
}