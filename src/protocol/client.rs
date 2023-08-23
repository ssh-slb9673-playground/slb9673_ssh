use std::io;
use std::net::SocketAddr;

use crate::crypto::{
    compression::NoneCompress, encryption::chachapoly::ChaCha20Poly1305,
    key_exchange::curve::Curve25519Sha256, mac::NoneMac,
};
use crate::network::tcp_client::TcpClient;
use crate::protocol::{
    data::Data,
    error::SshError,
    session::{NewKeys, Session},
};
use crate::utils::hexdump;

pub struct SshClient {
    client: TcpClient,
}

struct Config {
    address: SocketAddr,
    username: String,
}
enum SessionState {
    Version,
    KexInit,
    Kex,
    Auth,
}

impl SshClient {
    pub fn new(address: SocketAddr, username: String) -> io::Result<Self> {
        let client = TcpClient::new(address)?;
        Ok(SshClient { client })
    }

    pub fn connection_setup(&mut self) -> Result<(), SshError> {
        let (client_version, server_version) = self.version_exchange().unwrap();
        let mut session = Session::init_state();
        session.set_version(&client_version, &server_version);
        let (client_kex_algorithms, server_kex_algorithms) =
            self.key_exchange_init(&mut session).unwrap();
        session.set_kex_algorithms(&client_kex_algorithms, &server_kex_algorithms);
        let kex = self.key_exchange::<Curve25519Sha256>(&mut session)?;
        session.set_method(
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
        );
        println!(
            "{} {}",
            session.client_sequence_number, session.server_sequence_number
        );
        session.server_sequence_number = 3;

        let user_auth = self.user_auth(&mut session)?;
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
