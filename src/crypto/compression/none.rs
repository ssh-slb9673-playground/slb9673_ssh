use super::Compress;
use anyhow::Result;

pub struct NoneCompress {}
impl Compress for NoneCompress {
    fn compress(&self, msg: Vec<u8>) -> Result<Vec<u8>> {
        Ok(msg)
    }
    fn decompress(&self, msg: Vec<u8>) -> Result<Vec<u8>> {
        Ok(msg)
    }
}
