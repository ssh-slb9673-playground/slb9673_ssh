use crate::crypto::mac::MAC;

use super::key_exchange::Kex;

pub struct EncryptedPacket {
    packet_length: u32,
    encrypted_packet: Vec<u8>,
    mac: Vec<u8>,
}

impl EncryptedPacket {
    fn new<T: MAC>(encrypted_payload: &[u8], mac_method: T) -> Self {
        let packet_length = encrypted_payload.len() as u32;
        let mac = mac_method.generate(encrypted_payload);
        EncryptedPacket {
            packet_length,
            encrypted_packet: encrypted_payload.to_vec(),
            mac,
        }
    }
    fn generate_encrypted_packet(&self) {}
}
