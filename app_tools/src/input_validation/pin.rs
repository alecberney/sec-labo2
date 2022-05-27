use lazy_static::lazy_static;
use regex::Regex;

// Ref: https://developers.yubico.com/PIV/Introduction/Admin_access.html
static REGEX_PIN: &str = r"[[:alnum:]]{6,8}";

pub fn validate_pin(pin: &str) -> bool {
    lazy_static! {
        static ref RE: Regex = Regex::new(&format!("^{}$", REGEX_PIN)).unwrap();
    }
    RE.is_match(pin)
}

#[cfg(test)]
mod tests {
    use super::validate_pin;

    #[test]
    fn validate_pin_length() {
        // Pass
        assert!(validate_pin("0000000")); // 7

        // Fail
        assert!(!validate_pin(""));
        assert!(!validate_pin("0"));
        assert!(!validate_pin("0000000000000000000000000000000"));

        // Corner cases
        assert!(validate_pin("000000")); // 6
        assert!(validate_pin("00000000")); // 8
        assert!(!validate_pin("00000")); // 5
        assert!(!validate_pin("000000000")); // 9
    }

    #[test]
    fn validate_pin_characters() {
        // Pass & Corner cases
        assert!(validate_pin("0123456")); // num
        assert!(validate_pin("abcdefg")); // lower case
        assert!(validate_pin("ABCDEFG")); // upper case

        // Fail & Corner cases
        assert!(!validate_pin("$%/&£*+")); // special chars
        assert!(!validate_pin("._;!?<>")); // special chars
    }
}