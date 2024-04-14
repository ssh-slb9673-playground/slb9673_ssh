pub mod compression;
pub mod encryption;
pub mod key_exchange;
pub mod mac;
pub mod public_key;

use self::compression::CompressAdapter;
use self::encryption::EncryptionAdapter;
use self::key_exchange::KexMethodAdapter;
use self::mac::MACAdapter;
use self::public_key::PublicKeyAdapter;
use crate::protocol::data::{ByteString, DataType, NameList};
use nom::{
    error::{Error, ErrorKind, ParseError},
    Err, IResult,
};
use strum_macros::{AsRefStr, Display, EnumString};

pub struct CryptoAdapter {
    pub encrypt_adapter: Box<dyn EncryptionAdapter>,
    pub mac_adapter: Box<dyn MACAdapter>,
    pub compress_adapter: Box<dyn CompressAdapter>,
    pub key_exchange_adapter: Box<dyn KexMethodAdapter>,
    pub public_key_adapter: Box<dyn PublicKeyAdapter>,
}

/// key exchange algorithm
#[derive(Copy, Clone, PartialEq, Eq, AsRefStr, EnumString, Display)]
pub enum Kex {
    #[strum(serialize = "curve25519-sha256")]
    Curve25519Sha256,
    #[strum(serialize = "ecdh-sha2-nistp256")]
    EcdhSha2Nistrp256,
    #[cfg(feature = "deprecated-dh-group1-sha1")]
    #[strum(serialize = "diffie-hellman-group1-sha1")]
    DiffieHellmanGroup1Sha1,
    #[strum(serialize = "diffie-hellman-group14-sha1")]
    DiffieHellmanGroup14Sha1,
    #[strum(serialize = "diffie-hellman-group14-sha256")]
    DiffieHellmanGroup14Sha256,
}

/// pubkey hash algorithm
#[derive(Copy, Clone, PartialEq, Eq, AsRefStr, EnumString, Display)]
pub enum PubKey {
    #[strum(serialize = "ssh-ed25519")]
    SshEd25519,
    #[cfg(feature = "deprecated-rsa-sha1")]
    #[strum(serialize = "ssh-rsa")]
    SshRsa,
    #[strum(serialize = "rsa-sha2-256")]
    RsaSha2_256,
    #[strum(serialize = "rsa-sha2-512")]
    RsaSha2_512,
    #[cfg(feature = "deprecated-dss-sha1")]
    #[strum(serialize = "ssh-dss")]
    SshDss,
}

/// symmetrical encryption algorithm
#[derive(Copy, Clone, PartialEq, Eq, AsRefStr, EnumString, Display)]
pub enum Enc {
    #[strum(serialize = "chacha20-poly1305@openssh.com")]
    Chacha20Poly1305Openssh,
    #[strum(serialize = "aes128-ctr")]
    Aes128Ctr,
    #[strum(serialize = "aes192-ctr")]
    Aes192Ctr,
    #[strum(serialize = "aes256-ctr")]
    Aes256Ctr,
    #[cfg(feature = "deprecated-aes-cbc")]
    #[strum(serialize = "aes128-cbc")]
    Aes128Cbc,
    #[cfg(feature = "deprecated-aes-cbc")]
    #[strum(serialize = "aes192-cbc")]
    Aes192Cbc,
    #[cfg(feature = "deprecated-aes-cbc")]
    #[strum(serialize = "aes256-cbc")]
    Aes256Cbc,
    #[cfg(feature = "deprecated-des-cbc")]
    #[strum(serialize = "3des-cbc")]
    TripleDesCbc,
}

/// MAC(message authentication code) algorithm
#[derive(Copy, Clone, PartialEq, Eq, AsRefStr, EnumString, Display)]
pub enum Mac {
    #[strum(serialize = "hmac-sha1")]
    HmacSha1,
    #[strum(serialize = "hmac-sha2-256")]
    HmacSha2_256,
    #[strum(serialize = "hmac-sha2-512")]
    HmacSha2_512,
}

/// compression algorithm
#[derive(Copy, Clone, PartialEq, Eq, AsRefStr, EnumString, Display)]
pub enum Compress {
    #[strum(serialize = "none")]
    None,
    #[cfg(feature = "deprecated-zlib")]
    #[strum(serialize = "zlib")]
    Zlib,
    #[strum(serialize = "zlib@openssh.com")]
    ZlibOpenSsh,
}
