use std::{net::{SocketAddr, TcpStream}, io::{Result, BufReader, ErrorKind, Error, Write}};

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

    pub fn recv(&self) -> Result<Vec<u8>> {
        let socket = self.client.try_clone()?;
        let reader = BufReader::new(socket);
        let recv_data = reader.buffer();
        if recv_data.is_empty() {
            Err(Error::new(ErrorKind::UnexpectedEof, "oh no"))
        } else {
            Ok(recv_data.to_vec())
        }
    }
}