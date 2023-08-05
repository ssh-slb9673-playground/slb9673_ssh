// ssh-dss           REQUIRED     sign   Raw DSS Key
// string    "ssh-dss"
// mpint     p
// mpint     q
// mpint     g
// mpint     y
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

pub struct PublicKey {
    algorithm: PublicKeyAlgorithms,
    priv_key: Vec<u8>,
    pub_key: Vec<u8>,
}

impl PublicKey {
    // pub fn
}

// string    certificate or public key format identifier
// byte[n]   key/certificate data
