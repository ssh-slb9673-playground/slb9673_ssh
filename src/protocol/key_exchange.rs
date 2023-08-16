use nom::{AsBytes, IResult};

use crate::crypto::key_exchange::KexMethod;
use crate::protocol::utils::{ByteString, Data, DataType, Mpint};
use crate::protocol::{
    key_exchange_init::KexAlgorithms, ssh2::message_code, version_exchange::Version,
};

#[derive(Debug)]
pub struct Kex<T: KexMethod> {
    pub method: T,
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

// Initial IV client to server: HASH(K || H || "A" || session_id)
// Initial IV server to client: HASH(K || H || "B" || session_id)
// Encryption key client to server: HASH(K || H || "C" || session_id)
// Encryption key server to client: HASH(K || H || "D" || session_id)
// Integrity key client to server: HASH(K || H || "E" || session_id)
// Integrity key server to client: HASH(K || H || "F" || session_id)

// string   V_C, client's identification string (CR and LF excluded)
// string   V_S, server's identification string (CR and LF excluded)
// string   I_C, payload of the client's SSH_MSG_KEXINIT
// string   I_S, payload of the server's SSH_MSG_KEXINIT
// string   K_S, server's public host key
// string   Q_C, client's ephemeral public key octet string
// string   Q_S, server's ephemeral public key octet string
// mpint    K,   shared secret
// K1 = HASH(K || H || X || session_id) (X is e.g., "A")
// K2 = HASH(K || H || K1)
// K3 = HASH(K || H || K1 || K2)
// ...
// key = K1 || K2 || K3 || ...
impl<T: KexMethod> Kex<T> {
    pub fn new(
        method: T,
        client_version: &Version,
        server_version: &Version,
        client_kex: &KexAlgorithms,
        server_kex: &KexAlgorithms,
        server_public_host_key: &ByteString,
        client_public_key: &ByteString,
        server_public_key: &ByteString,
        shared_secret_key: &Mpint,
    ) -> Self {
        let mut data = Data::new();
        data.put(&ByteString(client_version.generate(false)))
            .put(&ByteString(server_version.generate(false)))
            .put(&ByteString(
                client_kex.generate_key_exchange_init().into_inner(),
            ))
            .put(&ByteString(
                server_kex.generate_key_exchange_init().into_inner(),
            ))
            .put(server_public_host_key)
            .put(client_public_key)
            .put(server_public_key)
            .put(shared_secret_key);
        let exchange_hash = method.hash(&data.into_inner());

        let alphabet = ['A', 'B', 'C', 'D', 'E', 'F'];
        let mut keys = Vec::new();
        for i in 0..6 {
            let mut key = Data::new();

            let mut seed = Data::new();
            seed.put(shared_secret_key)
                .put(&exchange_hash.as_bytes())
                .put(&(alphabet[i] as u8))
                .put(&exchange_hash.as_bytes());
            key.put(&method.hash(&seed.into_inner()).as_bytes());

            let mut seed = Data::new();
            seed.put(shared_secret_key)
                .put(&exchange_hash.as_bytes())
                .put(&key);
            key.put(&method.hash(&seed.into_inner()).as_bytes());

            keys.push(key.into_inner());
        }
        Kex::<T> {
            method,
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
}

pub fn parse_key_exchange<'a>(input: &'a [u8]) -> IResult<&'a [u8], (ByteString, ByteString)> {
    let (input, message_code) = u8::decode(input)?;
    assert!(message_code == message_code::SSH2_MSG_KEX_ECDH_REPLY);
    let (input, host_public_key) = ByteString::decode(input)?;
    let (input, public_key) = ByteString::decode(input)?;

    Ok((input, (host_public_key, public_key)))
}
