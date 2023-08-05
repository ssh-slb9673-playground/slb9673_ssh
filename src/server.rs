use std::io::{BufRead, BufReader, Error, ErrorKind, Result, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};

pub struct Server {
    pub address: SocketAddr,
    pub client: TcpStream,
}

impl Server {
    pub fn new(address: SocketAddr) -> Result<Self> {
        let listener = TcpListener::bind(address)?;
        // let mut sock = TcpStream::connect(SERVER_ADDRESS).expect("failed to connect server");
        listener.set_nonblocking(false).expect("out of service");
        let (client, address) = listener.accept()?;
        Ok(Server { address, client })
    }

    pub fn send(&self, response: &[u8]) -> Result<()> {
        let mut socket = self.client.try_clone()?;
        return socket.write_all(&response);
    }

    pub fn recv(&self) -> Result<String> {
        let socket = self.client.try_clone()?;
        let mut reader = BufReader::new(socket);
        let mut recv_data = String::new();
        let v = reader.read_line(&mut recv_data)?;
        if v > 0 {
            Ok(recv_data)
        } else {
            Err(Error::new(ErrorKind::UnexpectedEof, "oh no"))
        }
    }
}

#[test]
fn it_works() {
    let tx_mess = "Hello, TCP\r\n".as_bytes();
    // let server = Server::new("127.0.0.1:8080".parse().unwrap()).unwrap();
    // server.send(tx_mess).unwrap();
}
