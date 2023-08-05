use hmac::{Hmac, Mac};
use sha1::Sha1;

struct MAC {
    key: Vec<u8>,
    algorithm: MacAlgorithm,
}

// hmac-sha1    REQUIRED        HMAC-SHA1 (digest length = key length = 20)
// hmac-sha1-96 RECOMMENDED     first 96 bits of HMAC-SHA1 (digest length = 12, key length = 20)
// hmac-md5     OPTIONAL        HMAC-MD5 (digest length = key length = 16)
// hmac-md5-96  OPTIONAL        first 96 bits of HMAC-MD5 (digest length = 12, key length = 16)
// none         OPTIONAL        no MAC; NOT RECOMMENDED
enum MacAlgorithm {
    hmac_sha1,
    hmac_sha1_96,
    hmac_md5,
    hmac_md5_96,
    none,
}

impl MAC {
    pub fn generate_mac(&self, msg: Vec<u8>) -> Vec<u8> {
        type HmacSha1 = Hmac<Sha1>;
        match self.algorithm {
            MacAlgorithm::hmac_sha1 => {
                let mut mac =
                    Hmac::<Sha1>::new_from_slice(&self.key).expect("HMAC can take key of any size");
                mac.update(&msg);
                let result = mac.finalize();
                let code_bytes = result.into_bytes();
                code_bytes.to_vec()
            }
            MacAlgorithm::hmac_sha1_96 => {
                let mut mac =
                    Hmac::<Sha1>::new_from_slice(&self.key).expect("HMAC can take key of any size");
                mac.update(&msg);
                let result = mac.finalize();
                let code_bytes = result.into_bytes();
                code_bytes.to_vec()
            }
            _ => vec![],
        }
    }
}

#[test]
fn test() {
    let mut mac = Hmac::<Sha1>::new_from_slice(b"my secret and secure key")
        .expect("HMAC can take key of any size");
    mac.update(b"input message");

    let result: Vec<u8> = mac.finalize().into_bytes().to_vec();
    let expected =
        b"\x13\x3b\x67\xc6\x1c\x33\x95\xc1\x89\x35\x03\x8c\x86\xa7\x84\x46\xa4\x4d\xb7\x9f";
    assert_eq!(result[..], expected[..]);
}
