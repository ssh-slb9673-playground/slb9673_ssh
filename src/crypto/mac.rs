use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

// hmac-sha1    REQUIRED        HMAC-SHA1 (digest length = key length = 20)
// hmac-sha1-96 RECOMMENDED     first 96 bits of HMAC-SHA1 (digest length = 12, key length = 20)
// hmac-md5     OPTIONAL        HMAC-MD5 (digest length = key length = 16)
// hmac-md5-96  OPTIONAL        first 96 bits of HMAC-MD5 (digest length = 12, key length = 16)
// hmac-sha2-256     RECOMMENDED   HMAC-SHA2-256 (digest length = 32 bytes, key length = 32 bytes)
// hmac-sha2-512     OPTIONAL      HMAC-SHA2-512 (digest length = 64 bytes, key length = 64 bytes)
// none         OPTIONAL        no MAC; NOT RECOMMENDED
enum MacAlgorithm {
    HmacSha1,
    HmacSha1_96,
    HmacSha2_256,
    HmacSha2_512,
    HmacMd5,
    HmacMd5_96,
    None,
}

struct MAC {
    key: Vec<u8>,
    algorithm: MacAlgorithm,
}

impl MAC {
    pub fn new(key: Vec<u8>, algorithm: MacAlgorithm) -> Self {
        MAC { key, algorithm }
    }

    pub fn generate_mac(&self, msg: Vec<u8>) -> Vec<u8> {
        match self.algorithm {
            MacAlgorithm::HmacSha1 => {
                let mut mac = Hmac::<Sha1>::new_from_slice(&self.key).unwrap();
                mac.update(&msg);
                mac.finalize().into_bytes().to_vec()
            }
            MacAlgorithm::HmacSha1_96 => {
                let mut mac = Hmac::<Sha1>::new_from_slice(&self.key).unwrap();
                mac.update(&msg);
                mac.finalize().into_bytes().to_vec()
            }
            MacAlgorithm::HmacSha2_256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).unwrap();
                mac.update(&msg);
                mac.finalize().into_bytes().to_vec()
            }
            MacAlgorithm::HmacSha2_512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(&self.key).unwrap();
                mac.update(&msg);
                mac.finalize().into_bytes().to_vec()
            }
            _ => vec![],
        }
    }
}

#[test]
fn hmac_sha256() {
    // Create alias for HMAC-SHA256
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(b"my secret and secure key")
        .expect("HMAC can take key of any size");
    mac.update(b"input message");

    // `result` has type `CtOutput` which is a thin wrapper around array of
    // bytes for providing constant time equality check
    let result = mac.finalize();
    // To get underlying array use `into_bytes`, but be careful, since
    // incorrect use of the code value may permit timing attacks which defeats
    // the security provided by the `CtOutput`
    let code_bytes = result.into_bytes();
    let expected = b"\x97\xd2\xa5\x69\x05\x9b\xbc\xd8\xea\xd4\x44\x4f\xf9\x90\x71\xf4\xc0\x1d\x00\x5b\xce\xfe\x0d\x35\x67\xe1\xbe\x62\x8e\x5f\xdc\xd9";
    assert_eq!(code_bytes[..], expected[..]);
}
