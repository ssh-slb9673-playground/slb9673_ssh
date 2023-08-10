use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::{prelude::*, Result};

use super::Compress;

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
