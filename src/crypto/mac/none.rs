use super::MACAdapter;

pub struct NoneMac {}
impl MACAdapter for NoneMac {
    fn size(&self) -> usize {
        0
    }
    fn new(_key: Vec<u8>) -> Self {
        NoneMac {}
    }
    fn sign(&self, _msg: &[u8]) -> Vec<u8> {
        vec![]
    }
}
