// use rand::rngs::OsRng;
use rand_core::{CryptoRng, OsRng, RngCore};
use sha1::{Digest, Sha1};
use sha2::{Sha256, Sha512};
use x25519_dalek::{EphemeralSecret, PublicKey};

use super::public_key;

// diffie-hellman-group1-sha1 REQUIRED
// diffie-hellman-group14-sha1 REQUIRED
// curve25519-sha256
// curve448-sha512
trait KexMethod {
    fn new() -> Self;
    fn public_key(&self) -> Vec<u8>;
    fn shared_secret(&self, public_key: &[u8]) -> Vec<u8>;
    fn hash(&self, seed: &[u8]) -> Vec<u8>;
}

struct DiffieHellmanGroup1Sha1 {}
impl KexMethod for DiffieHellmanGroup1Sha1 {
    fn new() -> Self {
        DiffieHellmanGroup1Sha1 {}
    }
    fn public_key(&self) -> Vec<u8> {
        vec![]
    }
    fn shared_secret(&self, public_key: &[u8]) -> Vec<u8> {
        vec![]
    }
    fn hash(&self, seed: &[u8]) -> Vec<u8> {
        let mut hasher = Sha1::new();
        hasher.update(seed);
        hasher.finalize().as_slice().to_vec()
    }
}

struct DiffieHellmanGroup14Sha1 {}
impl KexMethod for DiffieHellmanGroup14Sha1 {
    fn new() -> Self {
        DiffieHellmanGroup14Sha1 {}
    }
    fn public_key(&self) -> Vec<u8> {
        vec![]
    }
    fn shared_secret(&self, public_key: &[u8]) -> Vec<u8> {
        vec![]
    }
    fn hash(&self, seed: &[u8]) -> Vec<u8> {
        let mut hasher = Sha1::new();
        hasher.update(seed);
        hasher.finalize().as_slice().to_vec()
    }
}

struct Curve25519Sha256 {
    private_key: EphemeralSecret,
    public_key: PublicKey,
}
impl KexMethod for Curve25519Sha256 {
    fn new() -> Self {
        let private_key = EphemeralSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);
        Curve25519Sha256 {
            private_key,
            public_key,
        }
    }
    fn public_key(&self) -> Vec<u8> {
        vec![]
    }
    fn shared_secret(&self, public_key: &[u8]) -> Vec<u8> {
        vec![]
    }
    fn hash(&self, seed: &[u8]) -> Vec<u8> {
        let mut hasher = Sha512::new();
        hasher.update(seed);
        hasher.finalize().as_slice().to_vec()
    }
}

struct Curve448Sha512 {}
impl KexMethod for Curve448Sha512 {
    fn new() -> Self {
        Curve448Sha512 {}
    }
    fn public_key(&self) -> Vec<u8> {
        vec![]
    }
    fn shared_secret(&self, public_key: &[u8]) -> Vec<u8> {
        vec![]
    }
    fn hash(&self, seed: &[u8]) -> Vec<u8> {
        let mut hasher = Sha512::new();
        hasher.update(seed);
        hasher.finalize().as_slice().to_vec()
    }
}

struct Kex<T: KexMethod> {
    method: T,
    shared_secret_key: Vec<u8>,
    exchange_hash: Vec<u8>,
    session_id: Vec<u8>,
}

// Initial IV client to server: HASH(K || H || "A" || session_id) (Here K is encoded as mpint and "A" as byte and session_id as raw data.  "A" means the single character A, ASCII 65).
// Initial IV server to client: HASH(K || H || "B" || session_id)
// Encryption key client to server: HASH(K || H || "C" || session_id)
// Encryption key server to client: HASH(K || H || "D" || session_id)
// Integrity key client to server: HASH(K || H || "E" || session_id)
// Integrity key server to client: HASH(K || H || "F" || session_id)
impl<T: KexMethod> Kex<T> {
    pub fn initiali_iv_client_to_server(&self) -> Vec<u8> {
        let mut seed: Vec<u8> = vec![];
        seed.extend(&self.shared_secret_key);
        seed.extend(&self.exchange_hash);
        seed.extend("A".as_bytes());
        seed.extend(&self.session_id);
        self.method.hash(&seed)
    }

    pub fn initiali_iv_server_to_client(&self) -> Vec<u8> {
        let mut seed: Vec<u8> = vec![];
        seed.extend(&self.shared_secret_key);
        seed.extend(&self.exchange_hash);
        seed.extend("B".as_bytes());
        seed.extend(&self.session_id);
        self.method.hash(&seed)
    }

    pub fn encryption_key_client_to_server(&self) -> Vec<u8> {
        let mut seed: Vec<u8> = vec![];
        seed.extend(&self.shared_secret_key);
        seed.extend(&self.exchange_hash);
        seed.extend("C".as_bytes());
        seed.extend(&self.session_id);
        self.method.hash(&seed)
    }

    pub fn encryption_key_server_to_client(&self) -> Vec<u8> {
        let mut seed: Vec<u8> = vec![];
        seed.extend(&self.shared_secret_key);
        seed.extend(&self.exchange_hash);
        seed.extend("D".as_bytes());
        seed.extend(&self.session_id);
        self.method.hash(&seed)
    }

    pub fn integrity_key_client_to_server(&self) -> Vec<u8> {
        let mut seed: Vec<u8> = vec![];
        seed.extend(&self.shared_secret_key);
        seed.extend(&self.exchange_hash);
        seed.extend("E".as_bytes());
        seed.extend(&self.session_id);
        self.method.hash(&seed)
    }

    pub fn integrity_key_server_to_client(&self) -> Vec<u8> {
        let mut seed: Vec<u8> = vec![];
        seed.extend(&self.shared_secret_key);
        seed.extend(&self.exchange_hash);
        seed.extend("F".as_bytes());
        seed.extend(&self.session_id);
        self.method.hash(&seed)
    }
}

// #[test]
// fn ed25519_ecdh() {
//     let P = constants::ED25519_BASEPOINT_TABLE;
//     let a: Scalar = Scalar::from_bytes_mod_order([
//         0xef, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
//         0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//         0x00, 0x10,
//     ]);
//     let Q = &a * P;
//     let t = Q.compress();
//     println!("{:?}", t);
// }
