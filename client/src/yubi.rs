use std::io;
use std::io::Read;
use yubikey::{Context, YubiKey, piv, PinPolicy, TouchPolicy, MgmKey, Buffer};
use x509::SubjectPublicKeyInfo;


type YubiKeyResult<T> = yubikey::Result<T>;

pub struct Yubi;

impl Yubi {
    fn auto_yk() -> YubiKeyResult<YubiKey> {
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

    pub fn generate_keys() -> YubiKeyResult<Vec<u8>> {
        let mut yubikey = Yubi::auto_yk()?;

        yubikey.authenticate(MgmKey::default())?;

        Ok(piv::generate(&mut yubikey,
                         piv::SlotId::Authentication,
                     piv::AlgorithmId::EccP256,
                     PinPolicy::Default,
                 TouchPolicy::Default)
            ?.public_key())
    }

    //https://docs.rs/yubikey/0.5.0/yubikey/piv/fn.sign_data.html -> to verify
    pub fn sign(bytes: &[u8]) -> YubiKeyResult<Buffer> {
        let mut yubikey = Yubi::auto_yk()?;
        //let raw: &[u8] = &[];

        yubikey.authenticate(MgmKey::default())?;

        //let data = "Hello World!".as_bytes();
        Ok(piv::sign_data(&mut yubikey,
                       bytes,
                       piv::AlgorithmId::EccP256,
                       piv::SlotId::Authentication)?)
    }
}