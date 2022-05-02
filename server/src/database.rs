use rustbreak::{FileDatabase, deser::Ron};
use std::collections::HashMap;
use std::error::Error;
use serde::{Serialize, Deserialize};
use crate::authentication::User;

lazy_static! {
    static ref DB: FileDatabase<Database, Ron> = FileDatabase::load_from_path_or_default("db.ron").unwrap();
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Database {
    data: HashMap<String, User>
}

impl Database {
    pub fn insert(user: &User) -> Result<(), Box<dyn Error>> {
        DB.write(|db| db.data.insert(user.email.clone(), user.clone()))?;
        Ok(DB.save()?)
    }

    pub fn get(email: &str) -> Result<Option<User>, Box<dyn Error>> {
        Ok(match DB.borrow_data()?.data.get(email) {
            Some(user) => Some(user.clone()),
            None => None
        })
    }
}

impl Default for Database {
    fn default() -> Self {
        Database{data: HashMap::new()}
    }
}