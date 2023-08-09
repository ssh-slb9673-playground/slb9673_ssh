use rand_core::OsRng;
use sha1::{Digest, Sha1};
use sha2::{Sha256, Sha512};
use x25519_dalek::{EphemeralSecret, PublicKey};

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

struct DiffieHellmanGroup1Sha1 {}
impl KexMethod for DiffieHellmanGroup1Sha1 {
    fn new() -> Self {
        DiffieHellmanGroup1Sha1 {}
    }
    fn public_key(&self) -> Vec<u8> {
        vec![]
    }
    fn shared_secret(&mut self, public_key: &[u8]) -> Vec<u8> {
        vec![]
    }
    fn hash(&self, seed: &[u8]) -> Vec<u8> {
        let mut hasher = Sha1::new();
        hasher.update(seed);
        hasher.finalize().as_slice().to_vec()
    }
}

pub struct DiffieHellmanGroup14Sha1 {}
impl KexMethod for DiffieHellmanGroup14Sha1 {
    fn new() -> Self {
        DiffieHellmanGroup14Sha1 {}
    }
    fn public_key(&self) -> Vec<u8> {
        vec![]
    }
    fn shared_secret(&mut self, public_key: &[u8]) -> Vec<u8> {
        vec![]
    }
    fn hash(&self, seed: &[u8]) -> Vec<u8> {
        let mut hasher = Sha1::new();
        hasher.update(seed);
        hasher.finalize().as_slice().to_vec()
    }
}

pub struct Curve25519Sha256 {
    private_key: Option<EphemeralSecret>,
    public_key: PublicKey,
}
impl KexMethod for Curve25519Sha256 {
    fn new() -> Self {
        let private_key = EphemeralSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);
        Curve25519Sha256 {
            private_key: Some(private_key),
            public_key,
        }
    }
    fn public_key(&self) -> Vec<u8> {
        self.public_key.to_bytes().to_vec()
    }
    fn shared_secret(&mut self, public_key: &[u8]) -> Vec<u8> {
        let public_key: [u8; 32] = public_key.try_into().unwrap();
        let public_key = PublicKey::from(public_key);
        let private_key = self.private_key.take().unwrap();
        let shared_secret = private_key.diffie_hellman(&public_key);
        shared_secret.to_bytes().to_vec()
    }
    fn hash(&self, seed: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.finalize().as_slice().to_vec()
    }
}

struct Curve448Sha512 {}
impl KexMethod for Curve448Sha512 {
    fn new() -> Self {
        Curve448Sha512 {}
    }
    fn public_key(&self) -> Vec<u8> {
        vec![]
    }
    fn shared_secret(&mut self, public_key: &[u8]) -> Vec<u8> {
        vec![]
    }
    fn hash(&self, seed: &[u8]) -> Vec<u8> {
        let mut hasher = Sha512::new();
        hasher.update(seed);
        hasher.finalize().as_slice().to_vec()
    }
}
