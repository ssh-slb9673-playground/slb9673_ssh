use super::PublicKey;

pub struct ssh_rsa {
    e: u64,
    n: u64,
}
impl PublicKey for ssh_rsa {
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

pub struct ssh_dss {
    p: u64,
    q: u64,
    g: u64,
    y: u64,
}
impl PublicKey for ssh_dss {
    fn identifier(&self) -> Vec<u8> {
        "ssh-dss".as_bytes().to_vec()
    }
    fn signature(&self) -> Vec<u8> {
        let mut result = vec![];
        result.extend(self.p.to_be_bytes());
        result.extend(self.q.to_be_bytes());
        result.extend(self.g.to_be_bytes());
        result.extend(self.y.to_be_bytes());
        result
    }
}
