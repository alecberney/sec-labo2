use lazy_static::lazy_static;
use regex::Regex;

static REGEX_PASSWORD_UPPER_CASE: &str = r"[[:upper:]]";
static REGEX_PASSWORD_LOWER_CASE: &str = r"[[:lower:]]";
static REGEX_PASSWORD_DIGIT: &str = r"\d";
static REGEX_PASSWORD_SPECIAL_CHAR: &str = r"[#?!@$ %^&*-]";
static REGEX_PASSWORD_GLOBAL: &str = r".{8,64}";

// TODO
/*Allow all possible characters (even space, Unicode). Very
annoying otherwise.
• Enforce a minimum length. 8 chars is the bare minimum.
• Have a maximum length. Too long passwords can lead to a DoS !
• Typical maximum length : 64 chars.*/

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
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }

    // TODO
}