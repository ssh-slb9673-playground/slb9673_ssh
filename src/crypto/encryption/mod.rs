use crate::protocol::{data::Data, error::SshError};

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
    // fn iv_size(&self) -> u32;
    // fn block_size(&self) -> u32;
    fn group_size(&self) -> u32;
    fn packet_length(&mut self, payload_length: u32) -> u32;
    fn encrypt(&mut self, buffer: &mut Data, sequence_number: u32);
    fn decrypt(&mut self, buffer: &mut [u8], sequence_number: u32) -> Result<Vec<u8>, SshError>;
}

#[derive(Debug, Clone)]
pub struct NoneEncryption {}
impl Encryption for NoneEncryption {
    // fn iv_size(&self) -> u32 {
    //     8
    // }
    // fn block_size(&self) -> u32 {
    //     8
    // }
    fn group_size(&self) -> u32 {
        8
    }
    fn packet_length(&mut self, payload_length: u32) -> u32 {
        let group_size = self.group_size();
        (payload_length + group_size - 1) / group_size * group_size + 4
    }

    fn encrypt(&mut self, _buffer: &mut Data, _sequence_number: u32) {}
    fn decrypt(&mut self, buffer: &mut [u8], _sequence_number: u32) -> Result<Vec<u8>, SshError> {
        Ok(buffer.to_vec())
    }
}
