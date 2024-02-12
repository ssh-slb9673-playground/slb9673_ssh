use super::key_exchange::Kex;
use super::key_exchange_init::KexAlgorithms;
use super::version_exchange::Version;
use crate::crypto::compression::none::NoneCompress;
use crate::crypto::encryption::none::NoneEncryption;
use crate::crypto::mac::none::NoneMac;
use crate::crypto::{compression::Compress, encryption::Encryption, mac::MAC};

pub struct NewKeys {
    pub enc: Box<dyn Encryption>,
    pub mac: Box<dyn MAC>,
    pub comp: Box<dyn Compress>,
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
        enc_method: Box<dyn Encryption>,
        mac_method: Box<dyn MAC>,
        comp_method: Box<dyn Compress>,
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

    pub fn set_version(&mut self, client_version: &Version, server_version: &Version) {
        self.client_version = Some(client_version.clone());
        self.server_version = Some(server_version.clone());
    }

    pub fn set_kex_algorithms(
        &mut self,
        client_kex_algorithms: &KexAlgorithms,
        server_kex_algorithms: &KexAlgorithms,
    ) {
        self.client_kex = Some(client_kex_algorithms.clone());
        self.server_kex = Some(server_kex_algorithms.clone());
    }

    pub fn set_method(&mut self, client_method: NewKeys, server_method: NewKeys) {
        self.client_method = client_method;
        self.server_method = server_method;
    }

    pub fn set_keys(&mut self, keys: Kex) {
        self.keys = Some(keys);
    }

    pub fn get_keys(&self) -> Kex {
        self.keys.clone().unwrap()
    }
}
