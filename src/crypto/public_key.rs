use strum_macros::{AsRefStr, EnumString};

pub mod ecc;
pub mod rsa;

// ssh-dss           REQUIRED     sign   Raw DSS Key
// ssh-rsa           RECOMMENDED  sign   Raw RSA Key
// pgp-sign-rsa      OPTIONAL     sign   OpenPGP certificates (RSA key)
// pgp-sign-dss      OPTIONAL     sign   OpenPGP certificates (DSS key)
// ssh-ed25519
// ssh-ed448

// string    certificate or public key format identifier
// byte[n]   key/certificate data
pub trait PublicKeyAdapter {
    fn identifier(&self) -> Vec<u8>;
    fn signature(&self) -> Vec<u8>;
}

/// pubkey hash algorithm
#[derive(Copy, Clone, PartialEq, Eq, AsRefStr, EnumString)]
pub enum PubKey {
    #[strum(serialize = "ssh-ed25519")]
    SshEd25519,
    #[cfg(feature = "dangerous-rsa-sha1")]
    #[strum(serialize = "ssh-rsa")]
    SshRsa,
    #[strum(serialize = "rsa-sha2-256")]
    RsaSha2_256,
    #[strum(serialize = "rsa-sha2-512")]
    RsaSha2_512,
}
