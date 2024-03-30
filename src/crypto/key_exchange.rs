use strum_macros::{AsRefStr, EnumString};

pub mod curve;
pub mod dh;

// diffie-hellman-group1-sha1 REQUIRED
// diffie-hellman-group14-sha1 REQUIRED
// curve25519-sha256
// curve448-sha512
pub trait KexMethodAdapter {
    fn new() -> Self
    where
        Self: Sized;
    fn public_key(&self) -> Vec<u8>;
    fn shared_secret(&mut self, public_key: &[u8]) -> Vec<u8>;
    fn hash(&self, seed: &[u8]) -> Vec<u8>;
}

/// key exchange algorithm
#[derive(Copy, Clone, PartialEq, Eq, AsRefStr, EnumString)]
pub enum Kex {
    #[strum(serialize = "curve25519-sha256")]
    Curve25519Sha256,
    #[strum(serialize = "ecdh-sha2-nistp256")]
    EcdhSha2Nistrp256,
    #[cfg(feature = "dangerous-dh-group1-sha1")]
    #[strum(serialize = "diffie-hellman-group1-sha1")]
    DiffieHellmanGroup1Sha1,
    #[strum(serialize = "diffie-hellman-group14-sha1")]
    DiffieHellmanGroup14Sha1,
    #[strum(serialize = "diffie-hellman-group14-sha256")]
    DiffieHellmanGroup14Sha256,
}
