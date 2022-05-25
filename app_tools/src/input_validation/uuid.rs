use lazy_static::lazy_static;
use regex::Regex;

// https://fr.wikipedia.org/wiki/Universally_unique_identifier
static REGEX_UUID: &str = r"[[:xdigit:]]{8}\-([[:xdigit:]]{4}\-){3}[[:xdigit:]]{12}";

pub fn validate_uuid(uuid: &str) -> bool {
    lazy_static! {
        static ref RE: Regex = Regex::new(&format!("^{}$", REGEX_UUID)).unwrap();
    }
    RE.is_match(uuid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_uuid_format() {
        // Pass
        assert!(validate_uuid("00000008-0004-0004-0004-000000000012"));

        // Fail
        assert!(!validate_uuid("000000000000000000000000000"));
        assert!(!validate_uuid("000000-000000-0000000000"));
        assert!(!validate_uuid("000000-000000-000000-0000"));
        assert!(!validate_uuid("--------------------------"));

        // Corner cases
        // the number at the end of the part is the number of characters from this one
        // we test higher and lower length from each part
        assert!(!validate_uuid("0000007-0004-0004-0004-000000000012"));
        assert!(!validate_uuid("000000009-0004-0004-0004-000000000012"));

        assert!(!validate_uuid("00000008-003-0004-0004-000000000012"));
        assert!(!validate_uuid("00000008-0004-003-0004-000000000012"));
        assert!(!validate_uuid("00000008-0004-0004-003-000000000012"));
        assert!(!validate_uuid("00000008-00005-0004-0004-000000000012"));
        assert!(!validate_uuid("00000008-0004-00005-0004-000000000012"));
        assert!(!validate_uuid("00000008-0004-0004-00005-000000000012"));

        assert!(!validate_uuid("00000008-0004-0004-003-00000000011"));
        assert!(!validate_uuid("00000008-0004-0004-003-0000000000013"));

        // we test the possibility of having 2 hyphens following each other
        assert!(!validate_uuid("00000008--0004-0004-0004-000000000012"));
        assert!(!validate_uuid("00000008-0004--0004-0004-000000000012"));
        assert!(!validate_uuid("00000008-0004-0004--0004-000000000012"));
        assert!(!validate_uuid("00000008-0004-0004-0004--000000000012"));

        // we test other characters than hyphens
        assert!(!validate_uuid("00000008 0004 0004 0004 000000000012"));
        assert!(!validate_uuid("00000008_0004_0004_0004_000000000012"));
        assert!(!validate_uuid("00000008000400040004000000000012"));
    }

    #[test]
    fn validate_uuid_characters() {
        // Pass
        assert!(validate_uuid("00000000-0000-0000-0000-000000000000"));
        assert!(validate_uuid("12345678-1234-4567-8912-123456789012"));
        assert!(validate_uuid("abcdefab-abcd-abcd-abcd-abcdefabcdef"));
        assert!(validate_uuid("ABCDEFAB-ABCD-ABCD-ABCD-ABCDEFABCDEF"));

        // Fail & Corner cases

        // we test special characters
        assert!(!validate_uuid("*$[_0000-0000-0000-0000-000000000000"));
        assert!(!validate_uuid("00000000-*$[_-0000-0000-000000000000"));
        assert!(!validate_uuid("00000000-0000-*$[_-0000-000000000000"));
        assert!(!validate_uuid("00000000-0000-0000-*$[_-000000000000"));
        assert!(!validate_uuid("00000000-0000-0000-0000-*$[_00000000"));
        assert!(!validate_uuid("+@*%&/()-=0?'-^`~]-[}{!-¨_<>°§:;.,00"));

        // we test non hex characters but alpha-numeric
        assert!(!validate_uuid("z0000000-0000-0000-0000-000000000000"));
        assert!(!validate_uuid("00000000-u000-0000-0000-000000000000"));
        assert!(!validate_uuid("00000000-0000-v000-0000-000000000000"));
        assert!(!validate_uuid("00000000-0000-0000-w000-000000000000"));
        assert!(!validate_uuid("00000000-0000-0000-0000-x00000000000"));
        assert!(!validate_uuid("z0000000-0000-0000-0000-000000000000"));

        assert!(!validate_uuid("Y0000000-0000-0000-0000-000000000000"));
        assert!(!validate_uuid("00000000-Z000-0000-0000-000000000000"));
        assert!(!validate_uuid("00000000-0000-U000-0000-000000000000"));
        assert!(!validate_uuid("00000000-0000-0000-V000-000000000000"));
        assert!(!validate_uuid("00000000-0000-0000-0000-W00000000000"));

        assert!(!validate_uuid("abcdefgh-ijkl-mnop-qrst-uvwxyz012345"));
        assert!(!validate_uuid("ABCDEFGH-IJKL-MNOP-QRST-UVWXYZ012345"));
    }
}