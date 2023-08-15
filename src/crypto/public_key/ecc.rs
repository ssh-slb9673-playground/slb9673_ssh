use super::PublicKey;

struct SshEd25519 {
    px: u64,
    py: u64,
}
impl PublicKey for SshEd25519 {
    fn identifier(&self) -> Vec<u8> {
        "ssh-ed25519".as_bytes().to_vec()
    }
    fn signature(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend(self.px.to_be_bytes());
        result
    }
}
