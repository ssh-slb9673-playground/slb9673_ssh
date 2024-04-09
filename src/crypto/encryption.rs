pub mod aes_ctr;
pub mod aes_gcm;
pub mod chachapoly;
pub mod none;

use crate::protocol::data::Data;
use strum_macros::{AsRefStr, EnumString};

// 3des-cbc         REQUIRED          three-key 3DES in CBC mode
// aes256-cbc       OPTIONAL          AES in CBC mode, with a 256-bit key
// aes192-cbc       OPTIONAL          AES with a 192-bit key
// aes128-cbc       RECOMMENDED       AES with a 128-bit key
// aes128 (cbc, ctr, gcm)	128 bits
// aes192 (cbc, ctr, gcm)	192 bits
// aes256 (cbc, ctr, gcm)	256 bits
pub trait EncryptionAdapter {
    // fn iv_size(&self) -> u32;
    // fn block_size(&self) -> u32;
    fn group_size(&self) -> u32;
    fn packet_length(&mut self, payload_length: u32) -> u32;
    fn encrypt(&mut self, buffer: &mut Data, sequence_number: u32);
    fn decrypt<'a>(
        &mut self,
        buffer: &'a mut [u8],
        sequence_number: u32,
    ) -> anyhow::Result<(&'a mut [u8], Vec<u8>, usize)>;
}

#[derive(Copy, Clone, PartialEq, Eq, AsRefStr, EnumString)]
pub enum Enc {
    #[strum(serialize = "chacha20-poly1305@openssh.com")]
    Chacha20Poly1305Openssh,
    #[strum(serialize = "aes128-ctr")]
    Aes128Ctr,
    #[strum(serialize = "aes192-ctr")]
    Aes192Ctr,
    #[strum(serialize = "aes256-ctr")]
    Aes256Ctr,
}
