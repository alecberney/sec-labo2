extern crate envfile;

use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use envfile::EnvFile;
use std::path::Path;
use std::error::Error;

// To use email, create a .env file at the root and add these values to it:
//SMTP_USER=x
//SMTP_PASS=x
//SMTP_SERV=x
//MAIL_FROM=x
fn read_env_file() -> Result<(String, String, String, String), Box<dyn Error>> {
    let envfile = EnvFile::new(&Path::new("./.env"))?;

    let mut smtp_user= String::from("");
    let mut smtp_pass= String::from("");
    let mut smtp_serv= String::from("");
    let mut mail_from= String::from("");

    for (key, value) in envfile.store {
        match &*key {
            "SMTP_USER" => smtp_user = format!("{}", value),
            "SMTP_PASS" => smtp_pass = format!("{}", value),
            "SMTP_SERV" => smtp_serv = format!("{}", value),
            "MAIL_FROM" => mail_from = format!("{}", value),
            _ => {}
        }
    }

    if smtp_user == "" || smtp_pass == "" || smtp_serv == "" || mail_from == "" {
        Err("INVALID ENV FILE".into())
    } else {
        Ok((smtp_user, smtp_pass, smtp_serv, mail_from))
    }
}

pub fn send_mail(dst: &str, subject: &str, message: &str) -> Result<(), Box<dyn Error>> {
    let (smtp_user, smtp_pass, smtp_serv, mail_from) = read_env_file()?;

    let email = Message::builder()
        .from(mail_from.parse().unwrap())
        .reply_to(mail_from.parse().unwrap())
        .to(dst.parse().unwrap())
        .subject(subject.to_string())
        .body(message.to_string())
        .unwrap();
    let creds = Credentials::new(smtp_user.to_string(), smtp_pass.to_string());

    let mailer = SmtpTransport::relay(&smtp_serv)
        .unwrap()
        .credentials(creds)
        .build();

    match mailer.send(&email) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Could not send email: {:?}", e).into()),
    }
}