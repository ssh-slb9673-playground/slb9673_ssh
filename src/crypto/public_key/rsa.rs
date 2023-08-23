use crate::protocol::data::{ByteString, Data, DataType};

use super::PublicKey;

// pub(super) struct RsaSha256;

// impl PublicKey for RsaSha256 {
//     fn identifier(&self) -> Vec<u8> {
//         "rsa-sha256".as_bytes().to_vec()
//     }
//     fn signature(&self, ks: &[u8], message: &[u8], sig: &[u8]) -> SshResult<bool> {
//         let mut data = Data(ks[4..].to_vec());
//         let _: ByteString = data.get();

//         let e = rsa::BigUint::from_bytes_be(&data.get::<ByteString>().to_bytes());
//         let n = rsa::BigUint::from_bytes_be(&data.get::<ByteString>().to_bytes());
//         let public_key = rsa::RsaPublicKey::new(n, e).unwrap();
//         let scheme = rsa::PaddingScheme::new_pkcs1v15_sign::<sha2::Sha256>();

//         let digest = ring::digest::digest(&ring::digest::SHA256, message);
//         let msg = digest.as_ref();

//         Ok(public_key.verify(scheme, msg, sig).is_ok())
//     }
// }
