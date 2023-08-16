use sha1::{Digest, Sha1};

use super::KexMethod;

struct DiffieHellmanGroup1Sha1 {}
impl KexMethod for DiffieHellmanGroup1Sha1 {
    fn new() -> Self {
        DiffieHellmanGroup1Sha1 {}
    }
    fn public_key(&self) -> Vec<u8> {
        Vec::new()
    }
    fn shared_secret(&mut self, _public_key: &[u8]) -> Vec<u8> {
        Vec::new()
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
        todo!()
    }
    fn shared_secret(&mut self, _public_key: &[u8]) -> Vec<u8> {
        todo!()
    }
    fn hash(&self, seed: &[u8]) -> Vec<u8> {
        let mut hasher = Sha1::new();
        hasher.update(seed);
        hasher.finalize().as_slice().to_vec()
    }
}
