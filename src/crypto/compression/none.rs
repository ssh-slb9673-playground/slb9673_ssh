use super::CompressAdapter;

pub struct NoneCompress {}
impl CompressAdapter for NoneCompress {
    fn compress(&self, msg: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        Ok(msg)
    }
    fn decompress(&self, msg: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        Ok(msg)
    }
}
