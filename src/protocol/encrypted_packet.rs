use crate::{
    crypto::{encryption::Encryption, mac::MAC},
    utils::{hex, hexdump},
};

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

    pub fn to_bytes(&mut self, payload: &[u8]) -> Vec<u8> {
        let packet = BinaryPacket::new(payload).to_bytes(self.sequence_number, &self.mac_method);
        hexdump(&packet);
        let encrypted_packet = self.enc_method.encrypt(&packet).unwrap();
        hexdump(&encrypted_packet);
        self.sequence_number += 1;
        encrypted_packet
    }
}
