use hmac::{Hmac, Mac};
use sha2::Sha256;

// hmac-sha1    REQUIRED        HMAC-SHA1 (digest length = key length = 20)
// hmac-sha1-96 RECOMMENDED     first 96 bits of HMAC-SHA1 (digest length = 12, key length = 20)
// hmac-md5     OPTIONAL        HMAC-MD5 (digest length = key length = 16)
// hmac-md5-96  OPTIONAL        first 96 bits of HMAC-MD5 (digest length = 12, key length = 16)
// none         OPTIONAL        no MAC; NOT RECOMMENDED
enum Mac {
    hmac_sha1,
    hmac_sha1_96,
    hmac_md5,
    hmac_md5_96,
    none,
}
type HmacSha256 = Hmac<Sha256>;

#[test]
fn test() {
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
