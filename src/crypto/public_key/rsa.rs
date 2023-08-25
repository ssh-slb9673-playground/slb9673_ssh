use rsa::pkcs1v15::SigningKey;
use rsa::signature::Signer;
use rsa::traits::PublicKeyParts;
use rsa::BigUint;
use sha2::Sha256;

use crate::protocol::data::{ByteString, Data, Mpint};
use crate::protocol::error::{SshError, SshResult};
use std::fs::File;
use std::io::Read;

pub struct RsaSha256 {
    pub public_key: rsa::RsaPublicKey,
    pub private_key: rsa::RsaPrivateKey,
}

impl RsaSha256 {
    pub fn read_from_file() -> SshResult<RsaSha256> {
        let mut file = match File::open("/home/anko/.ssh/id_rsa_ssh") {
            Ok(file) => file,
            Err(e) => return Err(SshError::from(e.to_string())),
        };
        let mut prks = String::new();
        file.read_to_string(&mut prks)
            .map_err(|_| SshError::RecvError("file".to_string()))?;

        let prk = ssh_key::PrivateKey::from_openssh(prks).unwrap();
        let rsa = prk.key_data().rsa().unwrap();
        let public_key = rsa::RsaPublicKey::new(
            BigUint::from_bytes_be(rsa.public.n.as_ref()),
            BigUint::from_bytes_be(rsa.public.e.as_ref()),
        )
        .map_err(|e| SshError::from(e.to_string()))?;
        let private_key = rsa::RsaPrivateKey::from_components(
            BigUint::from_bytes_be(rsa.public.n.as_ref()),
            BigUint::from_bytes_be(rsa.public.e.as_ref()),
            BigUint::from_bytes_be(rsa.private.d.as_ref()),
            vec![
                BigUint::from_bytes_be(rsa.private.p.as_ref()),
                BigUint::from_bytes_be(rsa.private.q.as_ref()),
            ],
        )
        .map_err(|e| SshError::from(e.to_string()))?;

        Ok(RsaSha256 {
            public_key,
            private_key,
        })
    }

    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let signing_key: SigningKey<Sha256> = SigningKey::<Sha256>::new(self.private_key.clone());
        let signature: Box<[u8]> = signing_key.sign(data).into();
        signature.to_vec()
    }

    pub fn public_key_blob(&self) -> ByteString {
        let mut pubkey_blob = Data::new();
        let e = Mpint(self.public_key.e().to_bytes_be().to_vec());
        let n = Mpint(self.public_key.n().to_bytes_be().to_vec());
        pubkey_blob.put(&"ssh-rsa".to_string()).put(&e).put(&n);
        ByteString(pubkey_blob.into_inner())
    }

    pub fn signature_blob(&self, msg: Data) -> ByteString {
        let mut signature_blob = Data::new();
        signature_blob.put(&"rsa-sha2-256".to_string());
        let signature = self.sign(&msg.into_inner());
        signature_blob.put(&ByteString(signature));
        ByteString(signature_blob.into_inner())
    }
}
