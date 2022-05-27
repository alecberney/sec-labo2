use std::io;
use std::io::Read;
use yubikey::{Context, YubiKey, piv, PinPolicy, TouchPolicy, MgmKey, Buffer};
use x509::SubjectPublicKeyInfo;
use crate::handlers::ask_pin;

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
        // I use default management key because implement an other is much harder
        // and it wasn't necessary for this testing lab.
        yubikey.authenticate(MgmKey::default())?;
        Ok(piv::generate(&mut yubikey,
                         piv::SlotId::Authentication,
                     piv::AlgorithmId::EccP256,
                     PinPolicy::Always,
                 TouchPolicy::Never)
            ?.public_key())
    }

    pub fn sign(bytes: &[u8]) -> YubiKeyResult<Buffer> {
        let mut yubikey = Yubi::auto_yk()?;
        yubikey.verify_pin(ask_pin().as_bytes())?;
        Ok(piv::sign_data(&mut yubikey,
                       bytes,
                       piv::AlgorithmId::EccP256,
                       piv::SlotId::Authentication)?)
    }
}