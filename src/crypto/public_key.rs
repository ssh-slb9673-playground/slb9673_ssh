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

pub struct PublicKey {
    algorithm: PublicKeyAlgorithms,
}

impl PublicKey {
    // pub fn
}

// string    certificate or public key format identifier
// byte[n]   key/certificate data
