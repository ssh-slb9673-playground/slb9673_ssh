use nom::AsBytes;
use rand::Rng;
use std::net::SocketAddr;

use super::{
    data::Data, error::SshResult, key_exchange_init::KexAlgorithms, session::Session,
    version_exchange::Version,
};
use crate::{crypto::key_exchange::curve::Curve25519Sha256, utils::hexdump};
use crate::{network::tcp_client::TcpClient, protocol::error::SshError};

pub struct SshClient {
    pub client: TcpClient,
    pub session: Session,
    pub config: Config,
    pub buffer: Vec<u8>,
}
pub struct Config {
    pub address: SocketAddr,
    pub username: String,
    pub service_name: String,
    pub version: Version,
    pub kex: KexAlgorithms,
}
impl SshClient {
    pub fn new(address: SocketAddr, username: String) -> SshResult<Self> {
        let client = TcpClient::new(address)?;
        let session = Session::init_state();
        let service_name = "ssh-connection".to_string();
        let config = Config {
            address,
            username,
            service_name,
            version: Version {
                version: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1".to_string(),
                crnl: true,
            },
            kex: KexAlgorithms {
                cookie: rand::thread_rng().gen::<[u8; 16]>(),
                kex_algorithms: vec!["curve25519-sha256".to_string()],
                server_host_key_algorithms: vec!["rsa-sha2-256".to_string()],
                encryption_algorithms_client_to_server: vec![
                    "chacha20-poly1305@openssh.com".to_string()
                ],
                encryption_algorithms_server_to_client: vec![
                    "chacha20-poly1305@openssh.com".to_string()
                ],
                mac_algorithms_client_to_server: vec!["hmac-sha2-256".to_string()],
                mac_algorithms_server_to_client: vec!["hmac-sha2-256".to_string()],
                compression_algorithms_client_to_server: vec!["none".to_string()],
                compression_algorithms_server_to_client: vec!["none".to_string()],
                languages_client_to_server: vec![],
                languages_server_to_client: vec![],
                first_kex_packet_follows: false,
                reserved: 0,
            },
        };
        Ok(SshClient {
            client,
            session,
            config,
            buffer: Vec::new(),
        })
    }

    pub fn connection_setup(&mut self) -> SshResult<()> {
        self.version_exchange()?;
        self.key_exchange_init()?;
        self.key_exchange::<Curve25519Sha256>()?;
        self.user_auth()?;
        Ok(())
    }

    //   uint32    packet_length
    //   byte      padding_length
    //   byte[n1]  payload; n1 = packet_length - padding_length - 1 Initially, compression MUST be "none".
    //   byte[n2]  random padding; n2 = padding_length
    //   byte[m]   mac (Message Authentication Code - MAC); m = mac_length Initially, the MAC algorithm MUST be "none".
    // mac = MAC(key, sequence_number || unencrypted_packet)
    pub fn send(&mut self, payload: &Data) -> SshResult<()> {
        let payload = payload.clone().into_inner();
        let payload_length = (payload.len() + 1) as u32;
        let packet_length = self.session.client_method.enc.packet_length(payload_length);
        let padding_length = (packet_length - payload_length) as u8;

        let mut data = Data::new();
        data.put(&packet_length)
            .put(&padding_length)
            .put(&payload.as_bytes())
            .put(&vec![0; padding_length as usize].as_bytes());

        println!("client -> server");
        data.hexdump();

        self.session
            .client_method
            .enc
            .encrypt(&mut data, self.session.client_sequence_number);
        data.put(
            &self
                .calc_mac(packet_length, padding_length, payload.as_bytes())
                .as_bytes(),
        );

        self.session.client_sequence_number += 1;
        self.client.send(&data.into_inner())
    }

    pub fn recv(&mut self) -> SshResult<Data> {
        let packet = if self.buffer.len() == 0 {
            let mut packet = self.client.recv()?;
            let (next, packet, _length) = self
                .session
                .client_method
                .enc
                .decrypt(&mut packet, self.session.server_sequence_number)?;
            self.buffer.extend_from_slice(&next);
            packet
        } else {
            let mut packet = self.buffer.clone();
            let (next, packet, length) = self
                .session
                .client_method
                .enc
                .decrypt(&mut packet, self.session.server_sequence_number)?;
            self.buffer.drain(..length);
            self.buffer.extend_from_slice(&next);
            packet
        };

        let mut packet = Data(packet);
        println!("server -> client");
        packet.hexdump();

        let packet_length: u32 = packet.get();
        let padding_length: u8 = packet.get();
        let payload_length = packet_length - padding_length as u32 - 1;
        let mac_length = self.session.server_method.mac.size();
        let payload: Vec<u8> = packet.get_bytes(payload_length as usize);
        let _padding: Vec<u8> = packet.get_bytes(padding_length as usize);
        let mac: Vec<u8> = packet.get_bytes(mac_length);

        if mac != self.calc_mac(packet_length, padding_length, payload.as_bytes()) {
            return Err(SshError::RecvError("".to_string()));
        }
        self.session.server_sequence_number += 1;

        Ok(Data(payload))
    }

    fn calc_mac(&self, packet_length: u32, padding_length: u8, payload: &[u8]) -> Vec<u8> {
        let mut data = Data::new();
        data.put(&self.session.client_sequence_number)
            .put(&packet_length)
            .put(&padding_length)
            .put(&payload)
            .put(&vec![0; padding_length as usize].as_bytes());
        self.session.server_method.mac.sign(&data.into_inner())
    }
}
