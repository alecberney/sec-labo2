use std::io;
use std::io::Read;
use yubikey::*;

pub struct Yubi;

impl Yubi {
    fn auto_yk() -> Result<YubiKey> {
        loop {
            for reader in Context::open()?.iter()? {
                if let Ok(yk) = reader.open() {
                    return Ok(yk);
                }
            }

            println!("No Yubikey detected: Please enter one and press [Enter] to continue...");
            let _ = io::stdin().read(&mut [0u8]).unwrap();
        }
    }

    // TODO
    pub fn generate_keys() -> Result<piv::PublicKeyInfo> {
        let yubikey = auto_yk()?;
        piv::generate(yubikey, piv::SlotId::Authentication, piv::ECCP256, Default, Default)
    }

    /*fn sign_data() -> Result<()> {
        let yubikey = auto_yk()?;
        let data = "Hello World!".as_bytes();
        piv::sign(yubikey, piv::SlotId::Authentication, data)
    }*/
}