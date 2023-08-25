use std::io::Read;
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::protocol::error::{SshError, SshResult};

pub struct TcpClient {
    pub address: SocketAddr,
    pub client: TcpStream,
}

impl TcpClient {
    pub fn new(address: SocketAddr) -> SshResult<Self> {
        let client = TcpStream::connect(address).expect("failed to connect server");
        client.set_nonblocking(false).expect("out of service");
        client
            .set_read_timeout(Some(Duration::new(3, 0)))
            .expect("set_read_timeout call failed");
        Ok(TcpClient { address, client })
    }

    pub fn send(&self, response: &[u8]) -> SshResult<()> {
        let mut socket = self
            .client
            .try_clone()
            .map_err(|_| SshError::RecvError("io".to_string()))?;
        socket
            .write_all(&response)
            .map_err(|_| SshError::RecvError("io".to_string()))
    }

    pub fn recv(&mut self) -> SshResult<Vec<u8>> {
        let mut recv_data = [0; 65535];
        loop {
            let packet_length = self
                .client
                .read(&mut recv_data)
                .map_err(|_| SshError::RecvError("io".to_string()))?;
            if packet_length > 0 {
                return Ok(recv_data[..packet_length].to_vec());
            }
        }
    }
}
