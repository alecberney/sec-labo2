use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

const SMTP_USER: &str = "alecberney";
const SMTP_PASS: &str = "dhzksgixhpdmjrce";
const SMTP_SERV: &str = "smtp.gmail.com";
const MAIL_FROM: &str = "AlecBerney <alecberney@gmail.com>";

// TODO: use env file

pub fn send_mail(dst: &str, subject: &str, message: &str) -> Result<(), String> {
    let email = Message::builder()
        .from(MAIL_FROM.parse().unwrap())
        .reply_to(MAIL_FROM.parse().unwrap())
        .to(dst.parse().unwrap())
        .subject(subject.to_string())
        .body(message.to_string())
        .unwrap();
    let creds = Credentials::new(SMTP_USER.to_string(), SMTP_PASS.to_string());

    let mailer = SmtpTransport::relay(SMTP_SERV)
        .unwrap()
        .credentials(creds)
        .build();

    match mailer.send(&email) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Could not send email: {:?}", e)),
    }
}