pub mod hmac;
pub mod none;

// hmac-sha1      REQUIRED        HMAC-SHA1 (digest length = key length = 20)
// hmac-sha1-96   RECOMMENDED     first 96 bits of HMAC-SHA1 (digest length = 12, key length = 20)
// hmac-md5       OPTIONAL        HMAC-MD5 (digest length = key length = 16)
// hmac-md5-96    OPTIONAL        first 96 bits of HMAC-MD5 (digest length = 12, key length = 16)
// hmac-sha2-256  RECOMMENDED     HMAC-SHA2-256 (digest length = 32 bytes, key length = 32 bytes)
// hmac-sha2-512  OPTIONAL        HMAC-SHA2-512 (digest length = 64 bytes, key length = 64 bytes)
// none           OPTIONAL        no MAC; NOT RECOMMENDED
pub trait MAC {
    fn size(&self) -> usize;
    fn new(key: Vec<u8>) -> Self
    where
        Self: Sized;
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
}
