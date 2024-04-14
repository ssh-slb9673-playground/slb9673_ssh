use super::client::SshClient;
use super::data::{ByteString, Data, Mpint};
use super::session::NewKeys;
use super::ssh2::message_code;
use crate::crypto::compression::none::NoneCompress;
use crate::crypto::encryption::chachapoly::ChaCha20Poly1305;
use crate::crypto::key_exchange::KexMethodAdapter;
use crate::crypto::mac::none::NoneMac;
use nom::AsBytes;

#[derive(Debug, Clone)]
pub struct Kex {
    pub shared_secret_key: Mpint,
    pub exchange_hash: Vec<u8>,
    pub session_id: Vec<u8>,
    pub client_initial_iv: Vec<u8>,
    pub server_initial_iv: Vec<u8>,
    pub client_encryption_key: Vec<u8>,
    pub server_encryption_key: Vec<u8>,
    pub client_integrity_key: Vec<u8>,
    pub server_integrity_key: Vec<u8>,
}

impl SshClient {
    pub fn key_exchange<Method: KexMethodAdapter>(&mut self) -> anyhow::Result<()> {
        let mut method = Method::new();

        let client_public_key = ByteString(method.public_key());
        self.send_pubkey(&client_public_key)?;

        let (server_public_host_key, server_public_key) = self.verify_signature_and_new_keys()?;

        let shared_secret = Mpint(method.shared_secret(&server_public_key.0));
        let exchange_hash = Kex::exchange_hash::<Method>(
            &method,
            &ByteString({
                let mut data = Data::new();
                data.put(
                    self.session
                        .client_version
                        .as_mut()
                        .unwrap()
                        .set_crnl(false),
                );
                data.into_inner()
            }),
            &ByteString({
                let mut data = Data::new();
                data.put(
                    self.session
                        .server_version
                        .as_mut()
                        .unwrap()
                        .set_crnl(false),
                );
                data.into_inner()
            }),
            &ByteString({
                let mut data = Data::new();
                data.put(&message_code::SSH_MSG_KEXINIT)
                    .put(self.session.client_kex.as_ref().unwrap());
                data.into_inner()
            }),
            &ByteString({
                let mut data = Data::new();
                data.put(&message_code::SSH_MSG_KEXINIT)
                    .put(self.session.server_kex.as_ref().unwrap());
                data.into_inner()
            }),
            &server_public_host_key,
            &client_public_key,
            &server_public_key,
            &shared_secret,
        );
        let kex = Kex::new::<Method>(method, exchange_hash, &shared_secret);

        // New Keys
        self.recv()?.expect(message_code::SSH_MSG_NEWKEYS);
        self.send(Data::new().put(&message_code::SSH_MSG_NEWKEYS))?;

        self.session.client_method = NewKeys::new(
            Box::new(ChaCha20Poly1305::new(
                &kex.client_encryption_key,
                &kex.server_encryption_key,
            )),
            Box::new(NoneMac {}),
            Box::new(NoneCompress {}),
        );
        self.session.server_method = NewKeys::new(
            Box::new(ChaCha20Poly1305::new(
                &kex.client_encryption_key,
                &kex.server_encryption_key,
            )),
            Box::new(NoneMac {}),
            Box::new(NoneCompress {}),
        );
        self.session.keys = Some(kex);
        Ok(())
    }

    fn send_pubkey(&mut self, pubkey: &ByteString) -> anyhow::Result<()> {
        let mut payload = Data::new();
        self.send(
            payload
                .put(&message_code::SSH2_MSG_KEX_ECDH_INIT)
                .put(pubkey),
        )
    }

    fn verify_signature_and_new_keys(&mut self) -> anyhow::Result<(ByteString, ByteString)> {
        println!("verify signature");
        let mut payload = self.recv()?;
        println!("{:?}", payload);
        payload.expect(message_code::SSH2_MSG_KEX_ECDH_REPLY);
        let server_public_host_key: ByteString = payload.get();
        let server_public_key: ByteString = payload.get();
        Ok((server_public_host_key, server_public_key))
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
    pub fn new<T: KexMethodAdapter>(
        method: T,
        exchange_hash: Vec<u8>,
        shared_secret_key: &Mpint,
    ) -> Self {
        let mut keys = Vec::new();
        for alphabet in ['A', 'B', 'C', 'D', 'E', 'F'] {
            let mut seed = Data::new();
            seed.put(shared_secret_key)
                .put(&exchange_hash.as_bytes())
                .put(&(alphabet as u8))
                .put(&exchange_hash.as_bytes());

            let mut key = Data::new();
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
            client_initial_iv: keys[0].clone(),
            server_initial_iv: keys[1].clone(),
            client_encryption_key: keys[2].clone(),
            server_encryption_key: keys[3].clone(),
            client_integrity_key: keys[4].clone(),
            server_integrity_key: keys[5].clone(),
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
    fn exchange_hash<T: KexMethodAdapter>(
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
