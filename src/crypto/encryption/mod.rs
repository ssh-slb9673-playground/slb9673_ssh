pub mod aes_ctr;
pub mod aes_gcm;
pub mod chachapoly;

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

pub struct NoneEncryption {}
impl Encryption for NoneEncryption {
    fn encrypt(&mut self, plaintext: &[u8]) -> Option<Vec<u8>> {
        Some(plaintext.to_vec())
    }
    fn decrypt(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        Some(ciphertext.to_vec())
    }
}
