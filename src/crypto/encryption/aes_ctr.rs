// use aes::cipher::KeyIvInit;
use aes::Aes128Ctr;
// use ctr::cipher::StreamCipher;

// use crate::utils::hex;

// use super::Encryption;

// type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;

// pub struct aes128_ctr {
//     cipher: Aes128Ctr64LE,
// }
// impl aes128_ctr {
//     pub fn new(key: &[u8], nonce: &[u8]) -> Self {
//         let cipher = Aes128Ctr64LE::new(key[..16].into(), nonce[..16].into());
//         // cipher.seek(0u32);
//         aes128_ctr { cipher }
//     }
// }
// impl Encryption for aes128_ctr {
//     fn encrypt(&mut self, plaintext: &[u8]) -> Option<Vec<u8>> {
//         let mut plaintext = plaintext.to_vec();
//         self.cipher.apply_keystream(&mut plaintext);
//         Some(plaintext.to_vec())
//     }
//     fn decrypt(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>> {
//         let mut ciphertext = ciphertext.to_vec();
//         self.cipher.apply_keystream(&mut ciphertext);
//         Some(ciphertext.to_vec())
//     }
// }
// #[test]
// fn encrypt_decrypt() {
//     let key = [
//         76, 221, 190, 22, 88, 43, 120, 83, 238, 242, 103, 43, 102, 166, 2, 140, 2, 69, 26, 90, 97,
//         71, 171, 14, 75, 109, 150, 117, 175, 54, 125, 201,
//     ];
//     let nonce = [
//         106, 248, 5, 76, 65, 174, 5, 214, 70, 140, 56, 45, 247, 51, 224, 53, 112, 107, 129, 95,
//         164, 162, 3, 156, 15, 42, 36, 93, 33, 214, 3, 134,
//     ];
//     let mut cipher = aes128_ctr::new(key[..16].into(), nonce[..16].into());
//     let plaintext = "test".as_bytes();
//     let ciphertext = cipher.encrypt(plaintext).unwrap();
//     let mut cipher = aes128_ctr::new(key[..16].into(), nonce[..16].into());
//     let buf = cipher.decrypt(&ciphertext).unwrap();
//     println!("{}", hex(plaintext));
//     println!("{}", hex(&buf));
//     assert_eq!(plaintext, &buf);
// }
