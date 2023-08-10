use std::io::Result;

pub mod zlib;

// none     REQUIRED        no compression
// zlib     OPTIONAL        ZLIB (LZ77) compression
pub trait Compress {
    fn compress(&self, msg: Vec<u8>) -> Result<Vec<u8>>;
    fn decompress(&self, msg: Vec<u8>) -> Result<Vec<u8>>;
}

pub struct NoneCompress {}
impl Compress for NoneCompress {
    fn compress(&self, msg: Vec<u8>) -> Result<Vec<u8>> {
        Ok(msg)
    }
    fn decompress(&self, msg: Vec<u8>) -> Result<Vec<u8>> {
        Ok(msg)
    }
}
