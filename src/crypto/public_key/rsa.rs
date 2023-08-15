use super::PublicKey;

pub struct SshRsa {
    e: u64,
    n: u64,
}
impl PublicKey for SshRsa {
    fn identifier(&self) -> Vec<u8> {
        "ssh-rsa".as_bytes().to_vec()
    }
    fn signature(&self) -> Vec<u8> {
        let mut result = vec![];
        result.extend(self.e.to_be_bytes());
        result.extend(self.n.to_be_bytes());
        result
    }
}
