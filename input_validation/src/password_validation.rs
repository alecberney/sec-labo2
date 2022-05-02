use lazy_static::lazy_static;
use regex::Regex;

// Start with maj, continue with alphanumeric, length 8 min
static REGEX_PASSWORD: &str = r"(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$ %^&*-]).{8,}";

// TODO
/*Allow all possible characters (even space, Unicode). Very
annoying otherwise.
• Enforce a minimum length. 8 chars is the bare minimum.
• Have a maximum length. Too long passwords can lead to a DoS !
• Typical maximum length : 64 chars.*/

pub fn validate_password(password_input: &str) -> bool {
    lazy_static! {
        static ref RE: Regex = Regex::new(&format!("^{}$", REGEX_PASSWORD)).unwrap();
    }
    RE.is_match(password_input)
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}