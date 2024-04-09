pub mod none;
pub mod zlib;

use strum_macros::{AsRefStr, EnumString};

// none     REQUIRED        no compression
// zlib     OPTIONAL        ZLIB (LZ77) compression
pub trait CompressAdapter {
    fn compress(&self, msg: Vec<u8>) -> anyhow::Result<Vec<u8>>;
    fn decompress(&self, msg: Vec<u8>) -> anyhow::Result<Vec<u8>>;
}

/// compression algorithm
#[derive(Copy, Clone, PartialEq, Eq, AsRefStr, EnumString)]
pub enum Compress {
    #[strum(serialize = "none")]
    None,
}
