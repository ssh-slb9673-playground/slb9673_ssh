use ed25519::signature::{Signer, Verifier};
use sha1::{Digest, Sha1};
use sha2::{Digest, Sha256, Sha512};

// diffie-hellman-group1-sha1 REQUIRED
// diffie-hellman-group14-sha1 REQUIRED
// curve25519-sha256
// curve448-sha512
enum KexMethod {
    DiffieHellmanGroup1Sha1,
    DiffieHellmanGroup14Sha1,
    Curve25519Sha256,
    Curve448Sha512,
}

struct Kex {
    method: KexMethod,
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
impl Kex {
    fn hash(&self, seed: Vec<u8>) -> Vec<u8> {
        match self.method {
            KexMethod::DiffieHellmanGroup14Sha1 | KexMethod::DiffieHellmanGroup1Sha1 => {
                let mut hasher = Sha1::new();
                hasher.update(seed);
                hasher.finalize().as_slice().to_vec()
            }
            KexMethod::Curve25519Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(seed);
                hasher.finalize().as_slice().to_vec()
            }
            KexMethod::Curve448Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(seed);
                hasher.finalize().as_slice().to_vec()
            }
        }
    }

    pub fn initiali_iv_client_to_server(&self) -> Vec<u8> {
        let mut seed: Vec<u8> = vec![];
        seed.extend(&self.shared_secret_key);
        seed.extend(&self.exchange_hash);
        seed.extend("A".as_bytes());
        seed.extend(&self.session_id);
        self.hash(seed)
    }

    pub fn initiali_iv_server_to_client(&self) -> Vec<u8> {
        let mut seed: Vec<u8> = vec![];
        seed.extend(&self.shared_secret_key);
        seed.extend(&self.exchange_hash);
        seed.extend("B".as_bytes());
        seed.extend(&self.session_id);
        self.hash(seed)
    }

    pub fn encryption_key_client_to_server(&self) -> Vec<u8> {
        let mut seed: Vec<u8> = vec![];
        seed.extend(&self.shared_secret_key);
        seed.extend(&self.exchange_hash);
        seed.extend("C".as_bytes());
        seed.extend(&self.session_id);
        self.hash(seed)
    }

    pub fn encryption_key_server_to_client(&self) -> Vec<u8> {
        let mut seed: Vec<u8> = vec![];
        seed.extend(&self.shared_secret_key);
        seed.extend(&self.exchange_hash);
        seed.extend("D".as_bytes());
        seed.extend(&self.session_id);
        self.hash(seed)
    }

    pub fn integrity_key_client_to_server(&self) -> Vec<u8> {
        let mut seed: Vec<u8> = vec![];
        seed.extend(&self.shared_secret_key);
        seed.extend(&self.exchange_hash);
        seed.extend("E".as_bytes());
        seed.extend(&self.session_id);
        self.hash(seed)
    }

    pub fn integrity_key_server_to_client(&self) -> Vec<u8> {
        let mut seed: Vec<u8> = vec![];
        seed.extend(&self.shared_secret_key);
        seed.extend(&self.exchange_hash);
        seed.extend("F".as_bytes());
        seed.extend(&self.session_id);
        self.hash(seed)
    }
}

#[test]
fn test() {
    pub struct HelloSigner<S>
    where
        S: Signer<ed25519::Signature>,
    {
        pub signing_key: S,
    }

    impl<S> HelloSigner<S>
    where
        S: Signer<ed25519::Signature>,
    {
        pub fn sign(&self, person: &str) -> ed25519::Signature {
            self.signing_key.sign(format_message(person).as_bytes())
        }
    }

    pub struct HelloVerifier<V> {
        pub verifying_key: V,
    }

    impl<V> HelloVerifier<V>
    where
        V: Verifier<ed25519::Signature>,
    {
        pub fn verify(
            &self,
            person: &str,
            signature: &ed25519::Signature,
        ) -> Result<(), ed25519::Error> {
            self.verifying_key
                .verify(format_message(person).as_bytes(), signature)
        }
    }

    fn format_message(person: &str) -> String {
        format!("Hello, {}!", person)
    }
}
