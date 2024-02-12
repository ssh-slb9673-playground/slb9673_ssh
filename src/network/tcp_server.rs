use anyhow::Result;
use std::io::{BufReader, Error, ErrorKind, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};

pub struct TcpServer {
    pub address: SocketAddr,
    pub client: TcpStream,
}

impl TcpServer {
    pub fn new(address: SocketAddr) -> Result<Self> {
        let listener = TcpListener::bind(address)?;
        listener.set_nonblocking(false).expect("out of service");
        let (client, address) = listener.accept()?;
        Ok(TcpServer { address, client })
    }

    pub fn send(&self, response: &[u8]) -> Result<()> {
        let mut socket = self.client.try_clone()?;
        socket.write_all(&response)?;
        Ok(())
    }

    pub fn recv(&self) -> Result<Vec<u8>> {
        let socket = self.client.try_clone()?;
        let reader = BufReader::new(socket);
        let recv_data = reader.buffer();
        if recv_data.is_empty() {
            Err(Error::new(ErrorKind::UnexpectedEof, "unexpected EOF").into())
        } else {
            Ok(recv_data.to_vec())
        }
    }
}

#[test]
fn connect_localhost() {
    let address = "127.0.0.1:8000";
    let listener = TcpListener::bind(address).unwrap();
    println!("{:?}", listener);
}
