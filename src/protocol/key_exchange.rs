use nom::{number::complete::be_u8, HexDisplay, IResult};
use std::vec;

use super::{key_exchange_init::KexAlgorithms, utils::generate_string, version_exchange::Version};
use crate::{
    crypto::{key_exchage::KexMethod, mpint::to_mpint},
    protocol::utils::parse_string,
    utils::{hex, hexdump},
};

#[derive(Debug)]
pub struct Kex<T: KexMethod> {
    pub method: T,
    pub shared_secret_key: Vec<u8>,
    pub exchange_hash: Vec<u8>,
    pub session_id: Vec<u8>,
}

// Initial IV client to server: HASH(K || H || "A" || session_id) (Here K is encoded as mpint and "A" as byte and session_id as raw data.  "A" means the single character A, ASCII 65).
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
impl<T: KexMethod> Kex<T> {
    pub fn new(
        method: T,
        session_id: &[u8],
        client_version: Version,
        server_version: Version,
        client_kex: &KexAlgorithms,
        server_kex: &KexAlgorithms,
        server_public_host_key: &[u8],
        client_public_key: &[u8],
        server_public_key: &[u8],
        shared_secret: &[u8],
    ) -> Self {
        let mut data = vec![];
        data.extend(generate_string(&client_version.to_bytes(false)));
        data.extend(generate_string(&server_version.to_bytes(false)));
        data.extend(generate_string(&client_kex.generate_key_exchange_init()));
        data.extend(generate_string(&server_kex.generate_key_exchange_init()));
        data.extend(generate_string(server_public_host_key));
        data.extend(generate_string(client_public_key));
        data.extend(generate_string(server_public_key));
        data.extend(generate_string(shared_secret));
        hexdump(&data);
        let exchange_hash = method.hash(&data);
        println!("shared_secret: {:?}", hex(&shared_secret));
        println!("exchange_hash: {:?}", hex(&exchange_hash));
        println!("session_id: {:?}", hex(&session_id));

        Kex::<T> {
            method,
            shared_secret_key: shared_secret.to_vec(),
            exchange_hash: exchange_hash.clone(),
            session_id: exchange_hash,
            // session_id: session_id.to_vec(),
        }
    }

    pub fn initial_iv_client_to_server(&self) -> Vec<u8> {
        let mut seed: Vec<u8> = vec![];
        seed.extend(&self.shared_secret_key);
        seed.extend(&self.exchange_hash);
        seed.extend("A".as_bytes());
        seed.extend(&self.session_id);
        self.method.hash(&seed)
    }

    pub fn initial_iv_server_to_client(&self) -> Vec<u8> {
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

pub fn parse_key_exchange<'a>(input: &'a [u8]) -> IResult<&'a [u8], (Vec<u8>, Vec<u8>)> {
    let (input, message_code) = be_u8(input)?;
    assert!(message_code == 31);
    // KEX host key
    let (input, host_public_key) = parse_string(input)?;
    let (input, public_key) = parse_string(input)?;

    Ok((input, (host_public_key, public_key)))
}

pub fn generate_key_exchange<T: KexMethod>(method: &T) -> Vec<u8> {
    let mut packet = vec![30];
    packet.extend(&generate_string(&method.public_key()));
    packet
}

/*
00000609  00 00 00 2c 06 1e 00 00  00 20 11 2e 9a 73 e2 53   ...,.... . ...s.S
00000619  7e 4e 71 dd 6e f7 fc ec  18 bb 3c 26 40 15 7e 3f   ~Nq.n... ..<&@.~?
00000629  80 7d de 27 f3 c8 f7 a0  59 12 00 00 00 00 00 00   .}.'.... Y.......
    000002E9  00 00 00 bc 08 1f 00 00  00 33 00 00 00 0b 73 73   ........ .3....ss
    000002F9  68 2d 65 64 32 35 35 31  39 00 00 00 20 e3 2a aa   h-ed2551 9... .*.
    00000309  79 15 ce b9 b4 49 d1 ba  50 ea 2a 28 bb 1a 6e 01   y....I.. P.*(..n.
    00000319  f9 0b da 24 5a 2d 1d 87  69 7d 18 a2 65 00 00 00   ...$Z-.. i}..e...
    00000329  20 8c 1b 73 02 25 bf 80  da 84 00 81 39 27 a5 7b    ..s.%.. ....9'.{
    00000339  52 ea db 1e 80 c2 24 42  fa 2c b0 56 3a c2 8f 3b   R.....$B .,.V:..;
    00000349  37 00 00 00 53 00 00 00  0b 73 73 68 2d 65 64 32   7...S... .ssh-ed2
    00000359  35 35 31 39 00 00 00 40  41 66 5f 8c 52 e5 82 88   5519...@ Af_.R...
    00000369  73 6b 1f b1 29 4b 0b dc  f8 b9 16 c6 cd 04 cd 4b   sk..)K.. .......K
    00000379  18 45 a0 95 4b b6 70 15  54 65 ef 67 5a 4c b3 99   .E..K.p. Te.gZL..
    00000389  ae 52 f0 c0 f3 19 96 64  ff a8 12 8a 4e cb 9d 2a   .R.....d ....N..*
    00000399  80 7a a0 4d 00 c3 93 09  00 00 00 00 00 00 00 00   .z.M.... ........
    000003A9  00 00 00 0c 0a 15 00 00  00 00 00 00 00 00 00 00   ........ ........
 */
