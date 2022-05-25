use lazy_static::lazy_static;
use regex::Regex;

//static REGEX_EMAIL: &str = r"[a-zA-Z0-9_+&*-]+(?:\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,7}";
static REGEX_EMAIL: &str = r#"(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"#;

pub fn validate_email(email_input: &str) -> bool {
    lazy_static! {
        static ref RE: Regex = Regex::new(&format!("^{}$", REGEX_EMAIL)).unwrap();
    }
    RE.is_match(email_input)
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }

    // TODO

    // Testing flag to bind test function with parametrized test cases.
    // Here, the fields input and expected are bound in the specified order, and then two sample test cases are provided.
    // TODO: provide more test cases to ensure that mail regex works properly, and to highlight its limits
    // Note : If a test case were to fail, it does not necessarily mean that the regex must be
    // corrected to work properly with it. It however should raise questions about whether those
    // limits are acceptable for the application or not.
    /*#[rstest(
    input,
    expected,
    case("toto", false), // Obviously wrong mail address should be invalid
    case("filipe.fortunato@heig-vd.ch", true), // Sample HEIG mail address should be valid
    // Pass
    case("a@a.aa", true),
    case("a.a@a.ch", true),
    case("a.a@a.a.ch", true),
    case("beral@sevjnet.ch", true),
    case("alec.berney@gmail.com", true),
    // Fail
    case("a", false),
    case("@a", false),
    case("@a.a", false),
    case("a@", false),
    case("a@.a", false),
    case("a@a", false),
    case("a@a.a", false),
    // Corner cases
    case("'><script>alert(1);</script>'@example.org", false),
    case("user+subaddress@example.org", true),
    case("user@[IPv6:2001:db8::1]", false),
    case("' '@example.org", false),
    ::trace // Traces testing for easier debugging
    )]
    pub fn mail_regex_test(input: &str, expected: bool) {
        // Write the test code based upon the provided parameters (input and expected output)
        lazy_static! {
            static ref mail_regex: Regex = Regex::new(MAIL_REGEX).unwrap();
        }
        assert_eq!(mail_regex.is_match(input), expected);
        //assert_eq!(validate_input(&mail_regex, input), expected);

        /*
        List of Valid Email Addresses

        email@example.com
        firstname.lastname@example.com
        email@subdomain.example.com
        firstname+lastname@example.com
        email@123.123.123.123
        email@[123.123.123.123]
        "email"@example.com
        1234567890@example.com
        email@example-one.com
        _______@example.com
        email@example.name
        email@example.museum
        email@example.co.jp
        firstname-lastname@example.com


        List of Strange Valid Email Addresses

        much.”more\ unusual”@example.com
        very.unusual.”@”.unusual.com@example.com
        very.”(),:;<>[]”.VERY.”very@\\ "very”.unusual@strange.example.com



        List of Invalid Email Addresses

        plainaddress
        #@%^%#$@#$@#.com
        @example.com
        Joe Smith <email@example.com>
        email.example.com
        email@example@example.com
        .email@example.com
        email.@example.com
        email..email@example.com
        あいうえお@example.com
        email@example.com (Joe Smith)
        email@example
        email@-example.com
        email@example.web
        email@111.222.333.44444
        email@example..com
        Abc..123@example.com


        List of Strange Invalid Email Addresses

        ”(),:;<>[\]@example.com
        just”not”right@example.com
        this\ is"really"not\allowed@example.com
         */
    }*/
}