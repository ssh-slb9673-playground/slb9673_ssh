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

pub struct CryptoAdapter {
    pub encrypt_adapter: Box<dyn EncryptionAdapter>,
    pub mac_adapter: Box<dyn MACAdapter>,
    pub compress_adapter: Box<dyn CompressAdapter>,
    pub key_exchange_adapter: Box<dyn KexMethodAdapter>,
    pub public_key_adapter: Box<dyn PublicKeyAdapter>,
}
