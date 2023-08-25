use nom::AsBytes;

use super::client::SshClient;
use super::data::{ByteString, Data, Mpint};
use super::error::SshResult;
use super::ssh2::message_code;
use crate::crypto::key_exchange::KexMethod;

#[derive(Debug, Clone)]
pub struct Kex {
    pub shared_secret_key: Mpint,
    pub exchange_hash: Vec<u8>,
    pub session_id: Vec<u8>,
    pub initial_iv_client_to_server: Vec<u8>,
    pub initial_iv_server_to_client: Vec<u8>,
    pub encryption_key_client_to_server: Vec<u8>,
    pub encryption_key_server_to_client: Vec<u8>,
    pub integrity_key_client_to_server: Vec<u8>,
    pub integrity_key_server_to_client: Vec<u8>,
}

impl SshClient {
    pub fn key_exchange<Method: KexMethod>(&mut self) -> SshResult<Kex> {
        let mut method = Method::new();

        let client_public_key = ByteString(method.public_key());
        self.send_pubkey(&client_public_key)?;

        let (server_public_host_key, server_public_key) = self.verify_signature_and_new_keys()?;

        let shared_secret = Mpint(method.shared_secret(&server_public_key.0));

        // New Keys
        self.new_keys()?;

        let exchange_hash = Kex::exchange_hash::<Method>(
            &method,
            &ByteString(
                self.session
                    .client_version
                    .as_mut()
                    .unwrap()
                    .set_crnl(false)
                    .pack(),
            ),
            &ByteString(
                self.session
                    .server_version
                    .as_mut()
                    .unwrap()
                    .set_crnl(false)
                    .pack(),
            ),
            &ByteString(
                self.session
                    .client_kex
                    .as_ref()
                    .unwrap()
                    .pack()
                    .into_inner(),
            ),
            &ByteString(
                self.session
                    .server_kex
                    .as_ref()
                    .unwrap()
                    .pack()
                    .into_inner(),
            ),
            &server_public_host_key,
            &client_public_key,
            &server_public_key,
            &shared_secret,
        );
        Ok(Kex::new::<Method>(method, exchange_hash, &shared_secret))
    }

    fn send_pubkey(&mut self, pubkey: &ByteString) -> SshResult<()> {
        let mut payload = Data::new();
        payload
            .put(&message_code::SSH2_MSG_KEX_ECDH_INIT)
            .put(pubkey);
        self.send(&payload)
    }

    fn verify_signature_and_new_keys(&mut self) -> SshResult<(ByteString, ByteString)> {
        let mut payload = self.recv()?;
        let message_code: u8 = payload.get();
        assert!(message_code == message_code::SSH2_MSG_KEX_ECDH_REPLY);
        let server_public_host_key: ByteString = payload.get();
        let server_public_key: ByteString = payload.get();
        Ok((server_public_host_key, server_public_key))
    }

    fn new_keys(&mut self) -> SshResult<()> {
        let mut payload = Data::new();
        payload.put(&message_code::SSH_MSG_NEWKEYS);
        self.send(&payload)
    }
}

impl Kex {
    // Initial IV client to server: HASH(K || H || "A" || session_id)
    // Initial IV server to client: HASH(K || H || "B" || session_id)
    // Encryption key client to server: HASH(K || H || "C" || session_id)
    // Encryption key server to client: HASH(K || H || "D" || session_id)
    // Integrity key client to server: HASH(K || H || "E" || session_id)
    // Integrity key server to client: HASH(K || H || "F" || session_id)

    // K1 = HASH(K || H || X || session_id) (X is e.g., "A")
    // K2 = HASH(K || H || K1)
    // K3 = HASH(K || H || K1 || K2)
    // ...
    // key = K1 || K2 || K3 || ...
    pub fn new<T: KexMethod>(method: T, exchange_hash: Vec<u8>, shared_secret_key: &Mpint) -> Self {
        let mut keys = Vec::new();
        for alphabet in ['A', 'B', 'C', 'D', 'E', 'F'] {
            let mut key = Data::new();

            let mut seed = Data::new();
            seed.put(shared_secret_key)
                .put(&exchange_hash.as_bytes())
                .put(&(alphabet as u8))
                .put(&exchange_hash.as_bytes());
            key.put(&method.hash(&seed.into_inner()).as_bytes());

            let mut seed = Data::new();
            seed.put(shared_secret_key)
                .put(&exchange_hash.as_bytes())
                .put(&key);
            key.put(&method.hash(&seed.into_inner()).as_bytes());

            keys.push(key.into_inner());
        }

        Kex {
            shared_secret_key: shared_secret_key.clone(),
            exchange_hash: exchange_hash.clone(),
            session_id: exchange_hash,
            initial_iv_client_to_server: keys[0].clone(),
            initial_iv_server_to_client: keys[1].clone(),
            encryption_key_client_to_server: keys[2].clone(),
            encryption_key_server_to_client: keys[3].clone(),
            integrity_key_client_to_server: keys[4].clone(),
            integrity_key_server_to_client: keys[5].clone(),
        }
    }

    // string   V_C, client's identification string (CR and LF excluded)
    // string   V_S, server's identification string (CR and LF excluded)
    // string   I_C, payload of the client's SSH_MSG_KEXINIT
    // string   I_S, payload of the server's SSH_MSG_KEXINIT
    // string   K_S, server's public host key
    // string   Q_C, client's ephemeral public key octet string
    // string   Q_S, server's ephemeral public key octet string
    // mpint    K,   shared secret
    fn exchange_hash<T: KexMethod>(
        method: &T,
        client_version: &ByteString,
        server_version: &ByteString,
        client_kex: &ByteString,
        server_kex: &ByteString,
        server_public_host_key: &ByteString,
        client_public_key: &ByteString,
        server_public_key: &ByteString,
        shared_secret_key: &Mpint,
    ) -> Vec<u8> {
        let mut data = Data::new();
        data.put(client_version)
            .put(server_version)
            .put(client_kex)
            .put(server_kex)
            .put(server_public_host_key)
            .put(client_public_key)
            .put(server_public_key)
            .put(shared_secret_key);
        method.hash(&data.into_inner())
    }
}
