// use aes_gcm::{
//     aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit, OsRng},
//     Aes128Gcm, Aes256Gcm, Key, Nonce,
// };

// use super::Encryption;

// pub struct aes256_gcm {
//     cipher: Aes256Gcm,
//     nonce: Nonce<typenum::U12>,
// }
// impl aes256_gcm {
//     pub fn new(key: &[u8], nonce: &[u8]) -> Self {
//         let key = Key::<Aes256Gcm>::from_slice(key);
//         let cipher = Aes256Gcm::new(key);
//         aes256_gcm {
//             cipher,
//             nonce: *GenericArray::from_slice(nonce),
//         }
//     }
// }
// impl Encryption for aes256_gcm {
//     fn encrypt(&mut self, plaintext: &[u8]) -> Option<Vec<u8>> {
//         self.cipher.encrypt(&self.nonce, plaintext).ok()
//     }
//     fn decrypt(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>> {
//         self.cipher.decrypt(&self.nonce, ciphertext).ok()
//     }
// }

// pub struct aes128_gcm {
//     cipher: Aes128Gcm,
//     nonce: Nonce<typenum::U12>,
// }
// impl aes128_gcm {
//     fn new(key: &[u8]) -> Self {
//         let key = Key::<Aes128Gcm>::from_slice(key);
//         let cipher = Aes128Gcm::new(key);
//         let nonce: Nonce<typenum::U12> = Aes128Gcm::generate_nonce(&mut OsRng);
//         aes128_gcm { cipher, nonce }
//     }
// }
// impl Encryption for aes128_gcm {
//     fn encrypt(&mut self, plaintext: &[u8]) -> Option<Vec<u8>> {
//         self.cipher.encrypt(&self.nonce, plaintext).ok()
//     }
//     fn decrypt(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>> {
//         self.cipher.decrypt(&self.nonce, ciphertext).ok()
//     }
// }
