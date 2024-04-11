use super::CompressAdapter;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::prelude::*;

pub struct Zlib {}
impl CompressAdapter for Zlib {
    fn compress(&self, msg: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(msg.as_slice())?;
        let compressed = encoder.finish()?;
        Ok(compressed)
    }

    fn decompress(&self, msg: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        let mut decoder = ZlibDecoder::new(msg.as_slice());
        let mut result = vec![];
        decoder.read_exact(&mut result)?;
        Ok(result)
    }
}
