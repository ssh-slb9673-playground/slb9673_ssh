use super::client::SshClient;
use super::data::{Data, DataType, NameList};
use super::ssh2::message_code;
use crate::crypto::{Compress, Enc, Kex, Mac, PubKey};
use rand::Rng;
use std::fmt::Debug;

#[derive(Debug, Clone)]
pub struct KexAlgorithms {
    pub cookie: [u8; 16],
    pub key_exchange: NameList,
    pub server_host_key: NameList,
    pub client_encryption: NameList,
    pub server_encryption: NameList,
    pub client_mac: NameList,
    pub server_mac: NameList,
    pub client_compression: NameList,
    pub server_compression: NameList,
    pub client_languages: NameList,
    pub server_languages: NameList,
    pub first_kex_packet_follows: bool,
    pub reserved: u32,
}

pub(crate) struct AlgList {
    pub key_exchange: Vec<Kex>,
    pub public_key: Vec<PubKey>,
    pub client_encryption: Vec<Enc>,
    pub server_encryption: Vec<Enc>,
    pub client_mac: Vec<Mac>,
    pub server_mac: Vec<Mac>,
    pub client_compress: Vec<Compress>,
    pub server_compress: Vec<Compress>,
}

impl AlgList {
    pub fn default() -> Self {
        AlgList {
            key_exchange: vec![Kex::Curve25519Sha256],
            public_key: vec![PubKey::RsaSha2_256],
            client_encryption: vec![Enc::Chacha20Poly1305Openssh],
            server_encryption: vec![Enc::Chacha20Poly1305Openssh],
            client_mac: vec![Mac::HmacSha2_256],
            server_mac: vec![Mac::HmacSha2_256],
            client_compress: vec![Compress::None],
            server_compress: vec![Compress::None],
        }
    }
}

impl SshClient {
    pub fn key_exchange_init(&mut self) -> anyhow::Result<()> {
        // recv key algorithms
        let mut payload = self.recv()?;
        payload.expect(message_code::SSH_MSG_KEXINIT);
        let server_kex_algorithms: KexAlgorithms = payload.get();

        // send key algorithms
        self.send(
            Data::new()
                .put(&message_code::SSH_MSG_KEXINIT)
                .put(&rand::thread_rng().gen::<[u8; 16]>())
                .put(&self.key_exchange),
        )?;

        self.session.client_kex = Some(self.key_exchange.clone());
        self.session.server_kex = Some(server_kex_algorithms.clone());

        tracing::info!("server algorithms: {:?}", server_kex_algorithms);
        println!("client algorithms: {:?}", self.key_exchange);

        Ok(())
    }
}

impl DataType for AlgList {
    fn decode(input: &[u8]) -> nom::IResult<&[u8], Self>
    where
        Self: Sized,
    {
        let (input, key_exchange) = <Vec<Kex>>::decode(input)?;
        let (input, public_key) = <Vec<PubKey>>::decode(input)?;
        let (input, client_encryption) = <Vec<Enc>>::decode(input)?;
        let (input, server_encryption) = <Vec<Enc>>::decode(input)?;
        let (input, client_mac) = <Vec<Mac>>::decode(input)?;
        let (input, server_mac) = <Vec<Mac>>::decode(input)?;
        let (input, client_compress) = <Vec<Compress>>::decode(input)?;
        let (input, server_compress) = <Vec<Compress>>::decode(input)?;
        let (input, _client_languages) = <NameList>::decode(input)?;
        let (input, _server_languages) = <NameList>::decode(input)?;
        let (input, _first_kex_packet_follows) = <bool>::decode(input)?;
        let (input, _reserved) = <u32>::decode(input)?;

        Ok((
            input,
            AlgList {
                key_exchange,
                public_key,
                client_encryption,
                server_encryption,
                client_mac,
                server_mac,
                client_compress,
                server_compress,
            },
        ))
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        self.key_exchange.encode(buf);
        self.public_key.encode(buf);
        self.client_encryption.encode(buf);
        self.server_encryption.encode(buf);
        self.client_mac.encode(buf);
        self.server_mac.encode(buf);
        self.client_compress.encode(buf);
        self.server_compress.encode(buf);
        let client_languages: NameList = vec![];
        client_languages.encode(buf);
        let server_languages: NameList = vec![];
        server_languages.encode(buf);
        let first_kex_packet_follows = false;
        first_kex_packet_follows.encode(buf);
        let reserved = 0u32;
        reserved.encode(buf);
    }
}

impl DataType for KexAlgorithms {
    fn decode(input: &[u8]) -> nom::IResult<&[u8], Self>
    where
        Self: Sized,
    {
        let (input, cookie) = <[u8; 16]>::decode(input)?;
        let (input, key_exchange) = <NameList>::decode(input)?;
        let (input, server_host_key) = <NameList>::decode(input)?;
        let (input, client_encryption) = <NameList>::decode(input)?;
        let (input, server_encryption) = <NameList>::decode(input)?;
        let (input, client_mac) = <NameList>::decode(input)?;
        let (input, server_mac) = <NameList>::decode(input)?;
        let (input, client_compression) = <NameList>::decode(input)?;
        let (input, server_compression) = <NameList>::decode(input)?;
        let (input, client_languages) = <NameList>::decode(input)?;
        let (input, server_languages) = <NameList>::decode(input)?;
        let (input, first_kex_packet_follows) = <bool>::decode(input)?;
        let (input, reserved) = <u32>::decode(input)?;

        Ok((
            input,
            KexAlgorithms {
                cookie,
                key_exchange,
                server_host_key,
                client_encryption,
                server_encryption,
                client_mac,
                server_mac,
                client_compression,
                server_compression,
                client_languages,
                server_languages,
                first_kex_packet_follows,
                reserved,
            },
        ))
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        self.cookie.encode(buf);
        self.key_exchange.encode(buf);
        self.server_host_key.encode(buf);
        self.client_encryption.encode(buf);
        self.server_encryption.encode(buf);
        self.client_mac.encode(buf);
        self.server_mac.encode(buf);
        self.client_compression.encode(buf);
        self.server_compression.encode(buf);
        self.client_languages.encode(buf);
        self.server_languages.encode(buf);
        self.first_kex_packet_follows.encode(buf);
        self.reserved.encode(buf);
    }
}

// When acting as server: "ext-info-s"
// When acting as client: "ext-info-c"
#[test]
fn parse_test_key_exchange_init_packet() {
    // \x00\x00\x05\xdc\x04\x14
    let mut payload = Data(b"\x14\x11\x58\xa5\x0f\xa6\x66\x70\x27\x00\x75\x6b\xd9\x62\xe5\xdc\xb2\
\x00\x00\x01\x14\
curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,sntrup761x25519-sha512@openssh.com,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,ext-info-c\
\x00\x00\x01\xcf\
ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256\
\x00\x00\x00\x6c\
chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com\
\x00\x00\x00\x6c\
chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com\
\x00\x00\x00\xd5\
umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1\
\x00\x00\x00\xd5\
umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1\
\x00\x00\x00\x1a\
none,zlib@openssh.com,zlib\
\x00\x00\x00\x1a\
none,zlib@openssh.com,zlib\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec());
    payload.expect(message_code::SSH_MSG_KEXINIT);
    let kex_algorithms: KexAlgorithms = payload.get();
    let mut gen_packet = Data::new();
    gen_packet
        .put(&message_code::SSH_MSG_KEXINIT)
        .put(&kex_algorithms);
    assert!(payload.into_inner() == gen_packet.into_inner());
}
