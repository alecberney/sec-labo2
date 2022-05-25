use lazy_static::lazy_static;
use regex::Regex;

static REGEX_PIN: &str = r".{6,8}";

pub fn validate_pin(pin: &str) -> bool {
    lazy_static! {
        static ref RE: Regex = Regex::new(&format!("^{}$", REGEX_PIN)).unwrap();
    }
    RE.is_match(pin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_pin_length() {
        // Pass
        assert!(validate_pin("0000000"));

        // Fail
        assert!(!validate_pin("0"));
        assert!(!validate_pin("0000000000000000000000000000000"));

        // Corner cases
        assert!(validate_pin("000000"));
        assert!(validate_pin("00000000"));
        assert!(validate_pin("00000"));
        assert!(validate_pin("000000000"));
    }
}