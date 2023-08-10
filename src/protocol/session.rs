use super::binary_packet::BinaryPacket;
use super::client;
use super::key_exchange_init::KexAlgorithms;
use super::version_exchange::Version;
use crate::crypto::compression::NoneCompress;
use crate::crypto::encryption::NoneEncryption;
use crate::crypto::mac::NoneMac;
use crate::crypto::{compression::Compress, encryption::Encryption, mac::MAC};
use crate::utils::{hex, hexdump};

// pub struct NewKeys<E: Encryption, M: MAC, C: Compress> {
//     pub enc_method: E,
//     pub mac_method: M,
//     pub comp_method: C,
// }

pub struct NewKeys {
    pub enc_method: Box<dyn Encryption>,
    pub mac_method: Box<dyn MAC>,
    pub comp_method: Box<dyn Compress>,
}

impl NewKeys {
    pub fn init_state() -> Self {
        NewKeys {
            enc_method: Box::new(NoneEncryption {}),
            mac_method: Box::new(NoneMac {}),
            comp_method: Box::new(NoneCompress {}),
        }
    }

    pub fn new(
        enc_method: Box<dyn Encryption>,
        mac_method: Box<dyn MAC>,
        comp_method: Box<dyn Compress>,
    ) -> Self {
        NewKeys {
            enc_method,
            mac_method,
            comp_method,
        }
    }
}

pub struct Session<'a> {
    pub client_method: NewKeys,
    pub server_method: NewKeys,

    pub client_sequence_number: u32,
    pub server_sequence_number: u32,

    pub client_version: Option<&'a Version>,
    pub server_version: Option<&'a Version>,

    pub client_kex: Option<&'a KexAlgorithms>,
    pub server_kex: Option<&'a KexAlgorithms>,
}

impl<'a> Session<'a> {
    pub fn init_state() -> Self {
        Session {
            client_method: NewKeys::init_state(),
            server_method: NewKeys::init_state(),
            client_sequence_number: 0,
            server_sequence_number: 0,
            client_version: None,
            server_version: None,
            client_kex: None,
            server_kex: None,
        }
    }

    pub fn new(
        client_method: NewKeys,
        server_method: NewKeys,
        client_version: &'a Version,
        server_version: &'a Version,
        client_kex: &'a KexAlgorithms,
        server_kex: &'a KexAlgorithms,
    ) -> Self {
        Session {
            client_method,
            server_method,
            client_sequence_number: 0,
            server_sequence_number: 0,
            client_version: Some(client_version),
            server_version: Some(server_version),
            client_kex: Some(client_kex),
            server_kex: Some(server_kex),
        }
    }

    pub fn encrypt_packet(&mut self, payload: &[u8], session: &Session) -> Vec<u8> {
        let packet = BinaryPacket::new(payload).to_bytes(session);
        hexdump(&packet);
        let encrypted_packet = self.client_method.enc_method.encrypt(&packet).unwrap();
        hexdump(&encrypted_packet);
        self.client_sequence_number += 1;
        encrypted_packet
    }

    pub fn parse(&self, packet: &[u8]) {}
}
