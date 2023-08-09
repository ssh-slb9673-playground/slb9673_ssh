use nom::ExtendInto;

use crate::crypto::{encryption::Encryption, mac::MAC};

use super::binary_packet::BinaryPacket;

pub struct EncryptedPacket<E: Encryption, M: MAC> {
    sequence_number: u32,
    enc_method: E,
    mac_method: M,
}

impl<E: Encryption, M: MAC> EncryptedPacket<E, M> {
    pub fn new(enc_method: E, mac_method: M) -> Self {
        EncryptedPacket {
            sequence_number: 0,
            enc_method,
            mac_method,
        }
    }
    pub fn generate_encrypted_packet(&self, payload: &[u8]) -> Vec<u8> {
        let packet = BinaryPacket::new(payload).generate_binary_packet();
        let mut encrypted_packet = self.enc_method.encrypt(&packet).unwrap();
        let mut data = self.sequence_number.to_be_bytes().to_vec();
        data.extend(encrypted_packet);
        let mac = self.mac_method.generate(&data);
        encrypted_packet.extend(&mac);
        encrypted_packet
    }
}
