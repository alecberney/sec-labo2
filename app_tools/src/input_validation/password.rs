use lazy_static::lazy_static;
use regex::Regex;

static REGEX_PASSWORD_UPPER_CASE: &str = r"[[:upper:]]";
static REGEX_PASSWORD_LOWER_CASE: &str = r"[[:lower:]]";
static REGEX_PASSWORD_DIGIT: &str = r"\d";
static REGEX_PASSWORD_SPECIAL_CHAR: &str = r"[#?!@$ %^&*-]";
static REGEX_PASSWORD_GLOBAL: &str = r".{8,64}";

pub fn validate_password(password_input: &str) -> bool {
    lazy_static! {
        static ref RE_UPPER: Regex = Regex::new(&format!("{}", REGEX_PASSWORD_UPPER_CASE)).unwrap();
        static ref RE_LOWER: Regex = Regex::new(&format!("{}", REGEX_PASSWORD_LOWER_CASE)).unwrap();
        static ref RE_DIGIT: Regex = Regex::new(&format!("{}", REGEX_PASSWORD_DIGIT)).unwrap();
        static ref RE_SPECIAL: Regex = Regex::new(&format!("{}", REGEX_PASSWORD_SPECIAL_CHAR)).unwrap();
        static ref RE_GLOBAL: Regex = Regex::new(&format!("^{}$", REGEX_PASSWORD_GLOBAL)).unwrap();
    }
    RE_UPPER.is_match(password_input) &&
        RE_LOWER.is_match(password_input) &&
        RE_DIGIT.is_match(password_input) &&
        RE_SPECIAL.is_match(password_input) &&
        RE_GLOBAL.is_match(password_input)
}

#[cfg(test)]
mod tests {
    use super::validate_password;

    #[test]
    fn validate_password_length() {
        // Pass
        assert!(validate_password("Test123456789$"));

        // Fail
        assert!(!validate_password("Te1$"));
        assert!(!validate_password("Teeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\
        eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeest1$")); // 100 chars

        // Corner cases
        assert!(validate_password("Test123$")); // 8 chars
        assert!(validate_password("Teeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\
        eeeeeeeeeest1$")); // 64 chars
        assert!(!validate_password("Test12$")); // 7 chars
        assert!(!validate_password("Teeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\
        eeeeeeeeeeeest1$")); // 65 chars
    }

    #[test]
    fn validate_password_characters() {
        // Pass
        assert!(validate_password("Test123456789$"));

        // Fail & Corner cases
        assert!(!validate_password("test123456789$")); // Without upper case
        assert!(!validate_password("TEST123456789$")); // Without lower case
        assert!(!validate_password("Testabcdefghi$")); // Without digit
        assert!(!validate_password("Test1234567890")); // Without special char
    }
}