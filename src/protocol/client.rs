use super::{
    data::{Data, DataType},
    key_exchange_init::{AlgList, KexAlgorithms},
    session::Session,
    version_exchange::Version,
};
use crate::crypto::key_exchange::curve::Curve25519Sha256;
use crate::{network::tcp_client::TcpClient, protocol::error::SshError};
use nom::{bytes::complete::take, AsBytes, IResult};
use rand::Rng;
use std::net::SocketAddr;

const SSH_CLIENT_VERSION: &str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1";
const SSH_CLIENT_SERVICE: &str = "ssh-connection";

// enum SessionState<S>
// where
//     S: Read + Write,
// {
//     Init(Config, S),
//     Version(Config, S),
//     Auth(SshClient, S),
//     Connected(SshClient, S),
// }
// fn connect(self) -> SshResult<Self> {
//     match self.inner {
//         SessionState::Init(config, stream) => SessionState::Version(config, stream).connect(),
//         SessionState::Version(mut config, mut stream) => {
//             info!("start for version negotiation.");
//             // Send Client version
//             config.ver.send_our_version(&mut stream)?;

//             // Receive the server version
//             config
//                 .ver
//                 .read_server_version(&mut stream, config.timeout)?;
//             // Version validate
//             config.ver.validate()?;

//             // from now on
//             // each step of the interaction is subject to the ssh constraints on the packet
//             // so we create a client to hide the underlay details
//             let client = Client::new(config);

//             Self {
//                 inner: SessionState::Auth(client, stream),
//             }
//             .connect()
//         }
//         SessionState::Auth(mut client, mut stream) => {
//             // before auth,
//             // we should have a key exchange at first
//             let mut digest = Digest::new();
//             let server_algs = SecPacket::from_stream(&mut stream, &mut client)?;
//             digest.hash_ctx.set_i_s(server_algs.get_inner());
//             let server_algs = AlgList::unpack(server_algs)?;
//             client.key_agreement(&mut stream, server_algs, &mut digest)?;
//             client.do_auth(&mut stream, &digest)?;
//             Ok(Self {
//                 inner: SessionState::Connected(client, stream),
//             })
//         }
//         _ => unreachable!(),
//     }
// }

#[derive(Debug, Clone)]
pub struct Config {
    pub username: String,
    pub password: String,
    pub private_key_path: String,
    pub service_name: String,
    pub version: Version,
}

pub struct SessionBuilder {
    config: Config,
}

impl SessionBuilder {
    pub fn create_session() -> Self {
        SessionBuilder {
            config: Config {
                username: String::from(""),
                password: String::from(""),
                private_key_path: String::from(""),
                service_name: SSH_CLIENT_SERVICE.to_string(),
                version: Version {
                    version: SSH_CLIENT_VERSION.to_string(),
                    crnl: true,
                },
            },
        }
    }

    pub fn username(mut self, username: &str) -> Self {
        self.config.username = username.to_string();
        self
    }

    pub fn password(mut self, password: &str) -> Self {
        self.config.password = password.to_string();
        self
    }

    pub fn private_key_path(mut self, path: &str) -> Self {
        self.config.private_key_path = path.to_string();
        self
    }

    pub fn connect(&self, address: SocketAddr) -> anyhow::Result<SshClient> {
        let mut client = SshClient {
            client: TcpClient::new(address)?,
            session: Session::init_state(),
            config: self.config.clone(),
            key_exchange: KexAlgorithms {
                cookie: rand::thread_rng().gen::<[u8; 16]>(),
                key_exchange: vec!["curve25519-sha256".to_string()],
                server_host_key: vec!["rsa-sha2-256".to_string()],
                client_encryption: vec!["chacha20-poly1305@openssh.com".to_string()],
                server_encryption: vec!["chacha20-poly1305@openssh.com".to_string()],
                client_mac: vec!["hmac-sha2-256".to_string()],
                server_mac: vec!["hmac-sha2-256".to_string()],
                client_compression: vec!["none".to_string()],
                server_compression: vec!["none".to_string()],
                client_languages: vec![],
                server_languages: vec![],
                first_kex_packet_follows: false,
                reserved: 0,
            },
            buffer: Vec::new(),
        };

        client.connection_setup()?;

        Ok(client)
    }
}

pub struct SshClient {
    pub client: TcpClient,
    pub session: Session,
    pub config: Config,
    pub buffer: Vec<u8>,
    pub key_exchange: KexAlgorithms,
    // pub state: SessionState,
}

impl SshClient {
    pub fn connection_setup(&mut self) -> anyhow::Result<()> {
        self.version_exchange()?;
        self.key_exchange_init()?;
        self.key_exchange::<Curve25519Sha256>()?;
        self.user_auth()?;
        Ok(())
    }
}

//   uint32    packet_length
//   byte      padding_length
//   byte[n1]  payload; n1 = packet_length - padding_length - 1 Initially, compression MUST be "none".
//   byte[n2]  random padding; n2 = padding_length
//   byte[m]   mac (Message Authentication Code - MAC); m = mac_length Initially, the MAC algorithm MUST be "none".
struct BinaryPacketProtocol {
    packet_length: u32,
    padding_length: u8,
    payload: Vec<u8>,
}

impl DataType for BinaryPacketProtocol {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.packet_length.encode(buf);
        self.padding_length.encode(buf);
        self.payload.as_bytes().encode(buf);
        vec![0; self.padding_length as usize].as_bytes().encode(buf);
    }

    fn decode(input: &[u8]) -> IResult<&[u8], Self>
    where
        Self: Sized,
    {
        let (input, packet_length) = <u32>::decode(input)?;
        let (input, padding_length) = <u8>::decode(input)?;
        let payload_length = packet_length - padding_length as u32 - 1;
        let (input, payload) = take(payload_length)(input)?;
        let (input, _padding) = take(padding_length as usize)(input)?;

        Ok((
            input,
            BinaryPacketProtocol {
                packet_length,
                padding_length,
                payload: payload.to_vec(),
            },
        ))
    }
}

impl SshClient {
    fn create_binary_packet(&mut self, payload: &Data) -> BinaryPacketProtocol {
        let payload = payload.clone().into_inner();
        let payload_length = (payload.len() + 1) as u32;
        let packet_length = self.session.client_method.enc.packet_length(payload_length);
        let padding_length = (packet_length - payload_length) as u8;

        BinaryPacketProtocol {
            packet_length,
            padding_length,
            payload,
        }
    }

    fn read_binary_packet_protocol(&mut self, payload: &mut Data) -> anyhow::Result<Data> {
        let packet: BinaryPacketProtocol = payload.get();

        let mac_length = self.session.server_method.mac.size();
        let mac: Vec<u8> = payload.get_bytes(mac_length);

        if mac != self.calc_mac(&packet) {
            return Err(SshError::RecvError("Don't match mac".to_string()).into());
        }

        Ok(Data(packet.payload))
    }

    // mac = MAC(key, sequence_number || unencrypted_packet)
    fn calc_mac(&self, packet: &BinaryPacketProtocol) -> Vec<u8> {
        let mut data = Vec::new();
        self.session.client_sequence_number.encode(&mut data);
        packet.encode(&mut data);
        self.session.server_method.mac.sign(&data)
    }
}

impl SshClient {
    pub fn send(&mut self, payload: &Data) -> anyhow::Result<()> {
        let packet = self.create_binary_packet(payload);

        let mut data = Data::new();
        data.put(&packet);

        println!("client -> server");
        data.hexdump();

        self.session
            .client_method
            .enc
            .encrypt(&mut data, self.session.client_sequence_number);

        data.put(&self.calc_mac(&packet).as_bytes());

        self.session.client_sequence_number += 1;
        self.client.send(&data.into_inner())
    }

    pub fn recv(&mut self) -> anyhow::Result<Data> {
        let mut packet = if !self.buffer.is_empty() {
            self.buffer.clone()
        } else {
            self.client.recv()?
        };

        let (next, packet, length) = self
            .session
            .client_method
            .enc
            .decrypt(&mut packet, self.session.server_sequence_number)?;

        if !self.buffer.is_empty() {
            self.buffer.drain(..length);
        }

        self.buffer.extend_from_slice(next);

        println!("server -> client");
        let mut packet = Data(packet);
        packet.hexdump();

        let payload = self.read_binary_packet_protocol(&mut packet)?;
        self.session.server_sequence_number += 1;
        Ok(payload)
    }
}
