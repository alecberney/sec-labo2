// TODO

//https://docs.rs/lettre/0.9.6/lettre/index.html

/*use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

const SMTP_USER: &str = "USERNAME";
const SMTP_PASS: &str = "PASSWORD";
const SMTP_SERV: &str = "SERVER_ADDR";
const MAIL_FROM: &str = "NoBody <nobody@localhost>";

pub fn send_otp_mail(dst: &str, otp: &str) -> Result<(), String> {
    let email = Message::builder()
        .from(MAIL_FROM.parse().unwrap())
        .reply_to(MAIL_FROM.parse().unwrap())
        .to(dst.parse().unwrap())
        .subject("Mail validation token")
        .body(format!("Here is the validation token : {}",otp))
        .unwrap();
    let creds = new(SMTP_USER.to_string(), SMTP_PASS.to_string());

    let mailer = SmtpTransport::relay(SMTP_SERV)
        .unwrap()
        .credentials(creds)
        .build();

    match mailer.send(&email) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Could not send email: {:?}", e)),
    }
}*/