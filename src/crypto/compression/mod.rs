use std::io::Result;

pub mod none;
pub mod zlib;

// none     REQUIRED        no compression
// zlib     OPTIONAL        ZLIB (LZ77) compression
pub trait Compress {
    fn compress(&self, msg: Vec<u8>) -> Result<Vec<u8>>;
    fn decompress(&self, msg: Vec<u8>) -> Result<Vec<u8>>;
}
