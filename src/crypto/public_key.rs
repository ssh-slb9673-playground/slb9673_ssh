pub mod ecc;
pub mod rsa;

// ssh-dss           REQUIRED     sign   Raw DSS Key
// ssh-rsa           RECOMMENDED  sign   Raw RSA Key
// pgp-sign-rsa      OPTIONAL     sign   OpenPGP certificates (RSA key)
// pgp-sign-dss      OPTIONAL     sign   OpenPGP certificates (DSS key)
// ssh-ed25519
// ssh-ed448

// string    certificate or public key format identifier
// byte[n]   key/certificate data
trait PublicKey {
    fn identifier(&self) -> Vec<u8>;
    fn signature(&self) -> Vec<u8>;
}
