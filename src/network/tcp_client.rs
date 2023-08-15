use std::io::Read;
use std::io::{Result, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

pub struct TcpClient {
    pub address: SocketAddr,
    pub client: TcpStream,
}

impl TcpClient {
    pub fn new(address: SocketAddr) -> Result<Self> {
        let client = TcpStream::connect(address).expect("failed to connect server");
        client.set_nonblocking(false).expect("out of service");
        client
            .set_read_timeout(Some(Duration::new(3, 0)))
            .expect("set_read_timeout call failed");
        Ok(TcpClient { address, client })
    }

    pub fn send(&self, response: &[u8]) -> Result<()> {
        let mut socket = self.client.try_clone()?;
        return socket.write_all(&response);
    }

    pub fn recv(&mut self) -> Result<Vec<u8>> {
        let mut recv_data = [0; 65535];
        loop {
            let packet_length = self.client.read(&mut recv_data)?;
            if packet_length > 0 {
                return Ok(recv_data[..packet_length].to_vec());
            }
        }
        // Err(Error::new(ErrorKind::UnexpectedEof, "oh no"))
    }
}
