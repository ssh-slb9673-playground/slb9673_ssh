use std::io::{BufRead, BufReader, Error, ErrorKind, Result, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};

pub struct TcpServer {
    pub address: SocketAddr,
    pub client: TcpStream,
}

impl TcpServer {
    pub fn new(address: SocketAddr) -> Result<Self> {
        let listener = TcpListener::bind(address)?;
        // let mut sock = TcpStream::connect(SERVER_ADDRESS).expect("failed to connect server");
        listener.set_nonblocking(false).expect("out of service");
        let (client, address) = listener.accept()?;
        Ok(TcpServer { address, client })
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
