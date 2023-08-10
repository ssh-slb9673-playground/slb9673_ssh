use aes::cipher::generic_array::GenericArray;
use aes_gcm::aead::Aead;
use aes_gcm::KeyInit;
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

use crate::utils::hex;

use super::Encryption;

pub struct chacha20_poly1305 {
    cipher: ChaCha20Poly1305,
    nonce: Nonce,
}

impl chacha20_poly1305 {
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        let cipher = ChaCha20Poly1305::new(key.into());
        println!("nonce: {}", hex(nonce));
        println!("key: {}", hex(key));
        chacha20_poly1305 {
            cipher,
            nonce: *GenericArray::from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]),
        }
    }
}
impl Encryption for chacha20_poly1305 {
    fn encrypt(&mut self, plaintext: &[u8]) -> Option<Vec<u8>> {
        self.cipher.encrypt(&self.nonce, plaintext).ok()
    }
    fn decrypt(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        self.cipher.decrypt(&self.nonce, ciphertext).ok()
    }
}
