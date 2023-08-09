use aes::cipher::KeyIvInit;
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit, OsRng},
    Aes128Gcm, Aes256Gcm, Key, Nonce,
};
use chacha20poly1305::ChaCha20Poly1305;
use ctr::cipher::StreamCipher;

use crate::utils::hex;

// 3des-cbc         REQUIRED          three-key 3DES in CBC mode
// aes256-cbc       OPTIONAL          AES in CBC mode, with a 256-bit key
// aes192-cbc       OPTIONAL          AES with a 192-bit key
// aes128-cbc       RECOMMENDED       AES with a 128-bit key
// aes128 (cbc, ctr, gcm)	128 bits
// aes192 (cbc, ctr, gcm)	192 bits
// aes256 (cbc, ctr, gcm)	256 bits

pub trait Encryption {
    fn encrypt(&mut self, plaintext: &[u8]) -> Option<Vec<u8>>;
    fn decrypt(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>>;
}

pub struct aes256_gcm {
    cipher: Aes256Gcm,
    nonce: Nonce<typenum::U12>,
}
impl aes256_gcm {
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        aes256_gcm {
            cipher,
            nonce: *GenericArray::from_slice(nonce),
        }
    }
}
impl Encryption for aes256_gcm {
    fn encrypt(&mut self, plaintext: &[u8]) -> Option<Vec<u8>> {
        self.cipher.encrypt(&self.nonce, plaintext).ok()
    }
    fn decrypt(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        self.cipher.decrypt(&self.nonce, ciphertext).ok()
    }
}

pub struct aes128_gcm {
    cipher: Aes128Gcm,
    nonce: Nonce<typenum::U12>,
}
impl aes128_gcm {
    fn new(key: &[u8]) -> Self {
        let key = Key::<Aes128Gcm>::from_slice(key);
        let cipher = Aes128Gcm::new(key);
        let nonce: Nonce<typenum::U12> = Aes128Gcm::generate_nonce(&mut OsRng);
        aes128_gcm { cipher, nonce }
    }
}
impl Encryption for aes128_gcm {
    fn encrypt(&mut self, plaintext: &[u8]) -> Option<Vec<u8>> {
        self.cipher.encrypt(&self.nonce, plaintext).ok()
    }
    fn decrypt(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        self.cipher.decrypt(&self.nonce, ciphertext).ok()
    }
}

pub struct aes128_ctr {
    cipher: ctr::Ctr128LE<aes::Aes128>,
}
impl aes128_ctr {
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        let cipher = ctr::Ctr128LE::<aes::Aes128>::new(key[..16].into(), nonce[..12].into());
        // cipher.seek(0u32);
        aes128_ctr { cipher }
    }
}
impl Encryption for aes128_ctr {
    fn encrypt(&mut self, plaintext: &[u8]) -> Option<Vec<u8>> {
        let mut plaintext = plaintext.to_vec();
        self.cipher.apply_keystream(&mut plaintext);
        Some(plaintext.to_vec())
    }
    fn decrypt(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let mut ciphertext = ciphertext.to_vec();
        self.cipher.apply_keystream(&mut ciphertext);
        Some(ciphertext.to_vec())
    }
}

pub struct chacha20_poly1305 {
    cipher: ChaCha20Poly1305,
    nonce: Nonce<typenum::U12>,
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
        self.cipher.encrypt(&self.nonce, ciphertext).ok()
    }
}
