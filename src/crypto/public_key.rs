// ssh-dss           REQUIRED     sign   Raw DSS Key
// ssh-rsa           RECOMMENDED  sign   Raw RSA Key
// pgp-sign-rsa      OPTIONAL     sign   OpenPGP certificates (RSA key)
// pgp-sign-dss      OPTIONAL     sign   OpenPGP certificates (DSS key)
// ssh-ed25519
// ssh-ed448
enum PublicKeyAlgorithms {
    ssh_dss,
    ssh_rsa,
    ssh_ed25519,
    ssh_ed448,
    pgp_sign_rsa,
    pgp_sign_dss,
}

// string    certificate or public key format identifier
// byte[n]   key/certificate data
trait PublicKey {
    fn identifier(&self) -> String;
    fn signature(&self) -> Vec<u8>;
}

pub struct ssh_rsa {
    e: u64,
    n: u64
}
impl PublicKey for ssh_rsa {
    fn identifier(&self) -> String {
        "ssh-rsa".to_string()
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
    y: u64
}
impl PublicKey for ssh_dss {
    fn identifier(&self) -> String {
        "ssh-dss".to_string()
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

struct ssh_ed25519 {
    px: u64,
    py: u64,
}
impl PublicKey for ssh_ed25519 {
    fn identifier(&self) -> String {
        "ssh-ed25519".to_string()
    }
    fn signature(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend(self.px.to_be_bytes());
        result
    }
}
