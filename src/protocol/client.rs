use nom::AsBytes;
use std::io;
use std::net::SocketAddr;

use crate::crypto::{
    compression::NoneCompress,
    encryption::chachapoly::ChaCha20Poly1305,
    key_exchange::{curve::Curve25519Sha256, KexMethod},
    mac::{HmacSha2_256, NoneMac, MAC},
};
use crate::network::tcp_client::TcpClient;
use crate::protocol::{
    binary_packet::SshPacket,
    data::{ByteString, Data, DataType, Mpint},
    error::SshError,
    key_exchange::{parse_key_exchange, Kex},
    key_exchange_init::KexAlgorithms,
    session::{NewKeys, Session},
    ssh2::message_code,
    version_exchange::Version,
};
use crate::utils::{hex, hexdump};

pub struct SshClient {
    address: SocketAddr,
    username: String,
    client: TcpClient,
    // dispatch: [Box<dyn Fn()>; 256],
}

impl SshClient {
    pub fn new(address: SocketAddr, username: String) -> io::Result<Self> {
        let client = TcpClient::new(address)?;
        Ok(SshClient {
            address,
            username,
            client,
        })
    }

    pub fn connection_setup(&mut self) -> Result<&[u8], SshError> {
        let mut session = Session::init_state();
        let (client_version, server_version) = self.version_exchange().unwrap();
        let (client_kex_algorithms, server_kex_algorithms) =
            self.key_exchange_init(&mut session).unwrap();
        let kex = self.key_exchange::<Curve25519Sha256>(
            &client_version,
            &server_version,
            &client_kex_algorithms,
            &server_kex_algorithms,
            &mut session,
        )?;

        let mut session = Session::new(
            NewKeys::new(
                Box::new(ChaCha20Poly1305::new(
                    &kex.encryption_key_client_to_server,
                    &kex.encryption_key_server_to_client,
                )),
                Box::new(NoneMac {}),
                Box::new(NoneCompress {}),
            ),
            NewKeys::new(
                Box::new(ChaCha20Poly1305::new(
                    &kex.encryption_key_client_to_server,
                    &kex.encryption_key_server_to_client,
                )),
                Box::new(NoneMac {}),
                Box::new(NoneCompress {}),
            ),
            &client_version,
            &server_version,
            &client_kex_algorithms,
            &server_kex_algorithms,
        );
        session.client_sequence_number += 3;
        session.server_sequence_number += 3;

        let user_auth = self.user_auth(&mut session)?;
        Ok(user_auth)
    }

    fn version_exchange(&mut self) -> Result<(Version, Version), SshError> {
        // send version
        let mut packet = Vec::new();
        let client_version = Version::new("SSH-2.0-OpenSSH_8.9p1", Some("Ubuntu-3ubuntu0.1"));
        client_version.generate(true).as_bytes().encode(&mut packet);
        self.send(&packet)?;

        // recv version
        let (_input, server_version) = Version::from_bytes(&self.recv()?)
            .map_err(|_| SshError::RecvError("version".to_string()))?;

        Ok((client_version, server_version))
    }

    fn key_exchange_init(
        &mut self,
        session: &mut Session,
    ) -> Result<(KexAlgorithms, KexAlgorithms), SshError> {
        // recv key algorithms
        let packet = self.recv()?;
        let (input, _binary_packet) =
            SshPacket::decode(&packet, session).map_err(|_| SshError::ParseError)?;
        let (_input, server_kex_algorithms) =
            KexAlgorithms::parse_key_exchange_init(input).map_err(|_| SshError::ParseError)?;

        // send key algorithms
        let client_kex_algorithms = server_kex_algorithms.create_kex_from_kex();
        let packet: SshPacket = client_kex_algorithms.generate_key_exchange_init().into();
        self.send(&packet.encode(session))?;

        Ok((client_kex_algorithms, server_kex_algorithms))
    }

    fn key_exchange<Method: KexMethod>(
        &mut self,
        client_version: &Version,
        server_version: &Version,
        client_kex: &KexAlgorithms,
        server_kex: &KexAlgorithms,
        session: &mut Session,
    ) -> Result<Kex<Method>, SshError> {
        let mut method = Method::new();
        let client_public_key = ByteString(method.public_key());

        let mut payload = Data::new();
        payload
            .put(&message_code::SSH2_MSG_KEX_ECDH_INIT)
            .put(&ByteString(method.public_key()));
        let packet: SshPacket = payload.into();
        self.send(&packet.encode(session))?;

        let key_exchange_packet = self.recv()?;
        let (payload, _binary_packet) =
            SshPacket::decode(&key_exchange_packet, session).map_err(|_| SshError::ParseError)?;
        let (_input, (server_public_host_key, server_public_key)) =
            parse_key_exchange(payload).map_err(|_| SshError::ParseError)?;

        let shared_secret = Mpint(method.shared_secret(&server_public_key.0));

        // New Keys
        let mut payload = Data::new();
        payload.put(&message_code::SSH_MSG_NEWKEYS);
        let packet: SshPacket = payload.into();
        self.send(&packet.encode(session))?;

        Ok(Kex::<Method>::new(
            method,
            client_version,
            server_version,
            client_kex,
            server_kex,
            &server_public_host_key,
            &client_public_key,
            &server_public_key,
            &shared_secret,
        ))
    }

    fn user_auth(&mut self, session: &mut Session) -> Result<&[u8], SshError> {
        let mut payload = Data::new();
        payload
            .put(&message_code::SSH_MSG_SERVICE_REQUEST)
            .put(&ByteString::from_str("ssh-userauth"));
        let packet: SshPacket = payload.into();
        self.send(&packet.encode(session))?;

        let mut payload = Data::new();
        payload
            .put(&message_code::SSH_MSG_USERAUTH_REQUEST)
            .put(&ByteString::from_str("anko"))
            .put(&ByteString::from_str("ssh-connection"))
            .put(&ByteString::from_str("publickey"))
            .put(&false)
            .put(&ByteString::from_str("rsa-sha2-256"));
        let packet: SshPacket = payload.into();
        self.send(&packet.encode(session))?;

        let packet = self.recv()?;
        hexdump(&packet);

        Ok(&[])
    }

    pub fn send(&self, packet: &[u8]) -> Result<(), SshError> {
        println!("client -> server");
        hexdump(packet);
        self.client
            .send(packet)
            .map_err(|_| SshError::SendError("io".to_string()))
    }

    pub fn recv(&mut self) -> Result<Vec<u8>, SshError> {
        let packet = self
            .client
            .recv()
            .map_err(|_| SshError::RecvError("io".to_string()))?;
        println!("server -> client");
        hexdump(&packet);
        Ok(packet)
    }
}
