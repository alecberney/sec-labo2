use lazy_static::lazy_static;
use regex::Regex;

static REGEX_EMAIL: &str = r#"(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"#;

pub fn validate_email(email_input: &str) -> bool {
    lazy_static! {
        static ref RE: Regex = Regex::new(&format!("^{}$", REGEX_EMAIL)).unwrap();
    }
    RE.is_match(email_input)
}

#[cfg(test)]
mod tests {
    use super::validate_email;

    #[test]
    fn validate_email_classical() {
        // Pass
        assert!(validate_email("email@example.com"));
        assert!(validate_email("firstname.lastname@example.com"));
        assert!(validate_email("email@subdomain.example.com"));
        assert!(validate_email("firstname+lastname@example.com"));
        assert!(validate_email("email@123.123.123.123"));
        assert!(validate_email("email@[123.123.123.123]"));
        assert!(validate_email("1234567890@example.com"));
        assert!(validate_email("_______@example.com"));
        assert!(validate_email("email@example.name"));
        assert!(validate_email("email@example.museum"));
        assert!(validate_email("email@example.co.jp"));
        assert!(validate_email("firstname-lastname@example.com"));

        assert!(validate_email("email@example.web"));
        assert!(validate_email("email@111.222.333.44444"));

        // Fail
        assert!(!validate_email("plainaddress"));
        assert!(!validate_email("#@%^%#$@#$@#.com"));
        assert!(!validate_email("@example.com"));
        assert!(!validate_email("Joe Smith <email@example.com>"));
        assert!(!validate_email("email.example.com"));
        assert!(!validate_email("email@example@example.com"));
        assert!(!validate_email(".email@example.com"));
        assert!(!validate_email("email.@example.com"));
        assert!(!validate_email("email..email@example.com"));
        assert!(!validate_email("あいうえお@example.com"));
        assert!(!validate_email("email@example.com (Joe Smith)"));
        assert!(!validate_email("email@example"));
        assert!(!validate_email("email@-example.com"));
        assert!(!validate_email("email@example..com"));
        assert!(!validate_email("Abc..123@example.com"));
    }

    #[test]
    fn validate_email_strange() {
        // Fail
        assert!(!validate_email("much.”more\\ unusual”@example.com"));
        assert!(!validate_email("very.unusual.”@”.unusual.com@example.com"));
        assert!(!validate_email("very.”(),:;<>[]”.VERY.”very@\\ \"very”.unusual@strange.example.com"));

        assert!(!validate_email("”(),:;<>[\\]@example.com"));
        assert!(!validate_email("just”not”right@example.com"));
        assert!(!validate_email("this\\ is\"really\"not\\allowed@example.com"));
    }
}