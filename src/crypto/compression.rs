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

pub struct Compress {
    algorithm: CompressionAlgorithm,
}

impl Compress {
    pub fn compress(&self, msg: Vec<u8>) -> Result<Vec<u8>> {
        match self.algorithm {
            CompressionAlgorithm::Zlib => {
                let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
                e.write_all(msg.as_slice())?;
                e.finish()
            }
            CompressionAlgorithm::None => Ok(msg),
        }
    }

    pub fn decompress(&self, msg: Vec<u8>) -> Result<Vec<u8>> {
        match self.algorithm {
            CompressionAlgorithm::Zlib => {
                let mut d = ZlibDecoder::new(msg.as_slice());
                let mut result = vec![];
                d.read(&mut result)?;
                Ok(result)
            }
            CompressionAlgorithm::None => Ok(msg),
        }
    }
}
