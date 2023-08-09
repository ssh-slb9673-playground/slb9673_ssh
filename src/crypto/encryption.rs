use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes128Gcm, Aes256Gcm, Key, Nonce,
};
use chacha20poly1305::ChaCha20Poly1305;

// 3des-cbc         REQUIRED          three-key 3DES in CBC mode
// aes256-cbc       OPTIONAL          AES in CBC mode, with a 256-bit key
// aes192-cbc       OPTIONAL          AES with a 192-bit key
// aes128-cbc       RECOMMENDED       AES with a 128-bit key
// aes128 (cbc, ctr, gcm)	128 bits
// aes192 (cbc, ctr, gcm)	192 bits
// aes256 (cbc, ctr, gcm)	256 bits

pub trait Encryption {
    fn encrypt(&self, plaintext: &[u8]) -> Option<Vec<u8>>;
    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>>;
}

pub struct aes256_gcm {
    cipher: Aes256Gcm,
    nonce: Nonce<typenum::U12>,
}
impl aes256_gcm {
    fn new(key: &[u8]) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        let nonce: Nonce<typenum::U12> = Aes256Gcm::generate_nonce(&mut OsRng);
        aes256_gcm { cipher, nonce }
    }
}
impl Encryption for aes256_gcm {
    fn encrypt(&self, plaintext: &[u8]) -> Option<Vec<u8>> {
        self.cipher.encrypt(&self.nonce, plaintext).ok()
    }
    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
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
    fn encrypt(&self, plaintext: &[u8]) -> Option<Vec<u8>> {
        self.cipher.encrypt(&self.nonce, plaintext).ok()
    }
    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        self.cipher.decrypt(&self.nonce, ciphertext).ok()
    }
}

pub struct chacha20_poly1305 {
    cipher: ChaCha20Poly1305,
    nonce: Nonce<typenum::U12>,
}
impl chacha20_poly1305 {
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message
        let cipher = ChaCha20Poly1305::new(&key);
        chacha20_poly1305 { cipher, nonce }
    }
}
impl Encryption for chacha20_poly1305 {
    fn encrypt(&self, plaintext: &[u8]) -> Option<Vec<u8>> {
        self.cipher.encrypt(&self.nonce, plaintext).ok()
    }
    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        self.cipher.encrypt(&self.nonce, ciphertext).ok()
    }
}
