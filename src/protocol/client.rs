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
    data::{ByteString, Data, DataType, Mpint, NameList},
    error::SshError,
    key_exchange::Kex,
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
            client_version,
            server_version,
            client_kex_algorithms,
            server_kex_algorithms,
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
        let (_input, server_version) = Version::from_bytes(&self.recv()?.into_inner())
            .map_err(|_| SshError::RecvError("version".to_string()))?;

        Ok((client_version, server_version))
    }

    fn key_exchange_init(
        &mut self,
        session: &mut Session,
    ) -> Result<(KexAlgorithms, KexAlgorithms), SshError> {
        // recv key algorithms
        let mut payload = self.recv()?.pack(session).unseal()?;
        let server_kex_algorithms = KexAlgorithms::parse_key_exchange_init(&mut payload);

        // send key algorithms
        let client_kex_algorithms = server_kex_algorithms.create_kex_from_kex();
        self.send(
            &client_kex_algorithms
                .generate_key_exchange_init()
                .pack(session)
                .seal(),
        )?;

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

        let mut payload = Data::new();
        payload
            .put(&message_code::SSH2_MSG_KEX_ECDH_INIT)
            .put(&ByteString(method.public_key()));
        self.send(&payload.pack(session).seal())?;

        let mut payload = self.recv()?.pack(session).unseal()?;
        let message_code: u8 = payload.get();
        assert!(message_code == message_code::SSH2_MSG_KEX_ECDH_REPLY);
        let server_public_host_key: ByteString = payload.get();
        let server_public_key: ByteString = payload.get();

        let shared_secret = Mpint(method.shared_secret(&server_public_key.0));

        // New Keys
        let mut payload = Data::new();
        payload.put(&message_code::SSH_MSG_NEWKEYS);
        self.send(&payload.pack(session).seal())?;

        let client_public_key = ByteString(method.public_key());
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
        self.send(&payload.pack(session).seal())?;

        let mut payload = self.recv()?.pack(session).unseal()?;
        let message_code: u8 = payload.get();
        assert!(message_code == message_code::SSH_MSG_SERVICE_ACCEPT);
        let service_name: ByteString = payload.get();
        println!("{:?}", String::from_utf8(service_name.0));

        let mut payload = Data::new();
        payload
            .put(&message_code::SSH_MSG_USERAUTH_REQUEST)
            .put(&ByteString::from_str("anko"))
            .put(&ByteString::from_str("ssh-connection"))
            .put(&ByteString::from_str("publickey"))
            .put(&true)
            .put(&ByteString::from_str("rsa-sha2-256"))
            .put(&ByteString::from_str("signature"));

        self.send(&payload.pack(session).seal())?;

        let mut payload = self.recv()?.pack(session).unseal()?;
        let message_code: u8 = payload.get();
        match message_code {
            message_code::SSH_MSG_SERVICE_ACCEPT => {
                let service_name: ByteString = payload.get();
                println!("{:?}", String::from_utf8(service_name.0));
            }
            message_code::SSH2_MSG_USERAUTH_PK_OK => {
                let pubkey_algo: ByteString = payload.get();
                let pubkey_blob: ByteString = payload.get();
            }
            message_code::SSH_MSG_USERAUTH_SUCCESS => {}
            message_code::SSH_MSG_USERAUTH_FAILURE => {
                println!("failure");
                let auth: NameList = payload.get();
                let success: bool = payload.get();
            }
            message_code::SSH_MSG_USERAUTH_BANNER => {
                let message: ByteString = payload.get();
                let language_tag: ByteString = payload.get();
            }
            _ => {
                panic!("unexpected message code")
            }
        }

        Ok(&[])
    }

    pub fn parse(&mut self, session: &mut Session) -> Result<(), SshError> {
        let mut payload = self.recv()?.pack(session).unseal()?;
        let message_code: u8 = payload.get();
        match message_code {
            message_code::SSH_MSG_SERVICE_REQUEST => {
                let service_name: ByteString = payload.get();
            }
            message_code::SSH_MSG_SERVICE_ACCEPT => {
                let service_name: ByteString = payload.get();
                println!("{:?}", String::from_utf8(service_name.0));
            }
            message_code::SSH2_MSG_USERAUTH_PK_OK => {
                let pubkey_algo: ByteString = payload.get();
                let pubkey_blob: ByteString = payload.get();
            }
            message_code::SSH_MSG_USERAUTH_SUCCESS => {}
            message_code::SSH_MSG_USERAUTH_FAILURE => {
                println!("failure");
                let auth: NameList = payload.get();
                let success: bool = payload.get();
            }
            message_code::SSH_MSG_USERAUTH_BANNER => {
                let message: ByteString = payload.get();
                let language_tag: ByteString = payload.get();
            }
            message_code::SSH_MSG_DISCONNECT => {
                let disconnect_code: u32 = payload.get();
                let description: ByteString = payload.get();
                let language_tag: ByteString = payload.get();
            }
            message_code::SSH_MSG_USERAUTH_REQUEST => {
                let user_name: ByteString = payload.get();
                let service_name: ByteString = payload.get();
                let method_name: String = payload.get();
                match method_name.as_str() {
                    "publickey" => {
                        let is_signature: bool = payload.get();
                        let pubkey_algo: String = payload.get();
                        let pubkey_blob: ByteString = payload.get();
                        let signature: ByteString = payload.get();
                    }
                    "password" => {
                        let is_first: bool = payload.get();
                        if is_first {
                            let password: String = payload.get();
                        } else {
                            let old_password: String = payload.get();
                            let new_password: String = payload.get();
                        }
                    }
                    "hostbased" => {
                        let host_pubkey_algo: String = payload.get();
                        let host_pubkey_cert: ByteString = payload.get();
                        let hostname: String = payload.get();
                        let username: String = payload.get();
                        let signature: ByteString = payload.get();
                    }
                    "none" => {
                        panic!("none auth");
                    }
                    _ => {
                        panic!("unknown");
                    }
                }
            }
            message_code::SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ => {
                let prompt: String = payload.get();
                let language_tag: String = payload.get();
            }
            _ => {
                panic!("unexpected message code")
            }
        }
        Ok(())
    }

    pub fn send(&self, packet: &[u8]) -> Result<(), SshError> {
        println!("client -> server");
        hexdump(packet);
        self.client
            .send(packet)
            .map_err(|_| SshError::SendError("io".to_string()))
    }

    pub fn recv(&mut self) -> Result<Data, SshError> {
        let packet = self
            .client
            .recv()
            .map_err(|_| SshError::RecvError("io".to_string()))?;
        let packet = Data(packet);
        println!("server -> client");
        packet.hexdump();
        Ok(packet)
    }
}
