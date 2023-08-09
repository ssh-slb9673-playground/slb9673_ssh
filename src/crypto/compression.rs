use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::{prelude::*, Result};

// none     REQUIRED        no compression
// zlib     OPTIONAL        ZLIB (LZ77) compression
enum CompressionAlgorithm {
    Zlib,
    None,
}

pub trait Compress {
    fn compress(&self, msg: Vec<u8>) -> Result<Vec<u8>>;
    fn decompress(&self, msg: Vec<u8>) -> Result<Vec<u8>>;
}

pub struct Zlib {}
impl Compress for Zlib {
    fn compress(&self, msg: Vec<u8>) -> Result<Vec<u8>> {
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(msg.as_slice())?;
        e.finish()
    }

    fn decompress(&self, msg: Vec<u8>) -> Result<Vec<u8>> {
        let mut d = ZlibDecoder::new(msg.as_slice());
        let mut result = vec![];
        d.read(&mut result)?;
        Ok(result)
    }
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
