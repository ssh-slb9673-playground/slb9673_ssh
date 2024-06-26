use super::key_exchange::Kex;
use super::key_exchange_init::KexAlgorithms;
use super::version_exchange::Version;
use crate::crypto::compression::none::NoneCompress;
use crate::crypto::encryption::none::NoneEncryption;
use crate::crypto::mac::none::NoneMac;
use crate::crypto::{compression::CompressAdapter, encryption::EncryptionAdapter, mac::MACAdapter};

pub struct NewKeys {
    pub enc: Box<dyn EncryptionAdapter>,
    pub mac: Box<dyn MACAdapter>,
    pub comp: Box<dyn CompressAdapter>,
}

impl NewKeys {
    pub fn init_state() -> Self {
        NewKeys {
            enc: Box::new(NoneEncryption {}),
            mac: Box::new(NoneMac {}),
            comp: Box::new(NoneCompress {}),
        }
    }

    pub fn new(
        enc_method: Box<dyn EncryptionAdapter>,
        mac_method: Box<dyn MACAdapter>,
        comp_method: Box<dyn CompressAdapter>,
    ) -> Self {
        NewKeys {
            enc: enc_method,
            mac: mac_method,
            comp: comp_method,
        }
    }
}

pub struct Session {
    pub client_method: NewKeys,
    pub server_method: NewKeys,

    pub client_sequence_number: u32,
    pub server_sequence_number: u32,

    pub client_version: Option<Version>,
    pub server_version: Option<Version>,

    pub client_kex: Option<KexAlgorithms>,
    pub server_kex: Option<KexAlgorithms>,

    pub keys: Option<Kex>,
}

impl Session {
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
            keys: None,
        }
    }

    pub fn get_keys(&self) -> Kex {
        self.keys.clone().unwrap()
    }
}
