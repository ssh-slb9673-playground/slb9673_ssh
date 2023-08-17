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
    data::Data,
    error::SshError,
    session::{NewKeys, Session},
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
