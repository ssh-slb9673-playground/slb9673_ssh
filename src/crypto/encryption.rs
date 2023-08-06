use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes128Gcm,
    Aes256Gcm,
    Key, // Or `Aes128Gcm`
    Nonce,
};

// 3des-cbc         REQUIRED          three-key 3DES in CBC mode
// aes256-cbc       OPTIONAL          AES in CBC mode, with a 256-bit key
// aes192-cbc       OPTIONAL          AES with a 192-bit key
// aes128-cbc       RECOMMENDED       AES with a 128-bit key
// aes128 (cbc, ctr, gcm)	128 bits
// aes192 (cbc, ctr, gcm)	192 bits
// aes256 (cbc, ctr, gcm)	256 bits

trait Encryption {
    fn encrypt(&self, msg: &[u8]) -> Option<Vec<u8>>;
    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>>;
}

struct aes256_gcm {
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
    fn encrypt(&self, msg: &[u8]) -> Option<Vec<u8>> {
        self.cipher.encrypt(&self.nonce, msg).ok()
    }
    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        self.cipher.decrypt(&self.nonce, ciphertext).ok()
    }
}

struct aes128_gcm {
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
    fn encrypt(&self, msg: &[u8]) -> Option<Vec<u8>> {
        self.cipher.encrypt(&self.nonce, msg).ok()
    }
    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        self.cipher.decrypt(&self.nonce, ciphertext).ok()
    }
}
