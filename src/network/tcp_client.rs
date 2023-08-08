use std::net::{SocketAddr, TcpStream};
use std::io::{Result, ErrorKind, Error, Write};
use std::io::Read;

pub struct TcpClient {
    pub address: SocketAddr,
    pub client: TcpStream,
}

impl TcpClient {
    pub fn new(address: SocketAddr) -> Result<Self> {
        let client = TcpStream::connect(address).expect("failed to connect server");
        Ok(TcpClient { address, client })
    }

    pub fn send(&self, response: &[u8]) -> Result<()> {
        let mut socket = self.client.try_clone()?;
        return socket.write_all(&response);
    }

    pub fn recv(&mut self) -> Result<Vec<u8>> {
        let mut recv_data = [0; 128];
		self.client.read(&mut recv_data)?;
        if recv_data.is_empty() {
            Err(Error::new(ErrorKind::UnexpectedEof, "oh no"))
        } else {
            Ok(recv_data.to_vec())
        }
    }
}