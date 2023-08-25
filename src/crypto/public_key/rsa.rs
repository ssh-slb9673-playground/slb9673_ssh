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
        file.read_to_string(&mut prks);

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
        println!("{:?}", rsa.public.n.as_ref());

        Ok(RsaSha256 {
            public_key,
            private_key,
        })
    }

    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        // self.private_key
        //     .sign(rsa::pkcs1v15::Pkcs1v15Sign, digest_in);
        let signing_key: SigningKey<Sha256> = SigningKey::<Sha256>::new(self.private_key.clone());
        let signature: Box<[u8]> = signing_key.sign(data).into();
        signature.to_vec()
        // assert_ne!(signature.to_bytes().as_ref(), data.as_slice());
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

// use rsa::RsaPrivateKey;
// use rsa::pkcs1v15::{SigningKey, VerifyingKey};
// use rsa::signature::{Keypair, RandomizedSigner, SignatureEncoding, Verifier};
// use rsa::sha2::{Digest, Sha256};

// let mut rng = rand::thread_rng();

// let bits = 2048;
// let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
// let signing_key = SigningKey::<Sha256>::new(private_key);
// let verifying_key = signing_key.verifying_key();

// // Sign
// let data = b"hello world";
// let signature = signing_key.sign_with_rng(&mut rng, data);
// assert_ne!(signature.to_bytes().as_ref(), data.as_slice());

// // Verify
// verifying_key.verify(data, &signature).expect("failed to verify");
