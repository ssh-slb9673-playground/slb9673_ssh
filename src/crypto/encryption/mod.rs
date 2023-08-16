use crate::protocol::error::SshError;

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
    fn group_size(&self) -> u32;
    fn encrypt(&mut self, buffer: &mut Vec<u8>, sequence_number: u32);
    fn decrypt(
        &mut self,
        buffer: &mut [u8],
        tag: &[u8],
        sequence_number: u32,
    ) -> Result<Vec<u8>, SshError>;
}

pub struct NoneEncryption {}
impl Encryption for NoneEncryption {
    fn group_size(&self) -> u32 {
        8
    }
    fn encrypt(&mut self, buffer: &mut Vec<u8>, _sequence_number: u32) {}
    fn decrypt(
        &mut self,
        _buffer: &mut [u8],
        _tag: &[u8],
        _sequence_number: u32,
    ) -> Result<Vec<u8>, SshError> {
        Ok(Vec::new())
    }
}
