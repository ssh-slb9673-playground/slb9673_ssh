pub mod curve;
pub mod dh;

// diffie-hellman-group1-sha1 REQUIRED
// diffie-hellman-group14-sha1 REQUIRED
// curve25519-sha256
// curve448-sha512
pub trait KexMethod {
    fn new() -> Self;
    fn public_key(&self) -> Vec<u8>;
    fn shared_secret(&mut self, public_key: &[u8]) -> Vec<u8>;
    fn hash(&self, seed: &[u8]) -> Vec<u8>;
}
