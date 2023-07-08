mod config;
use std::io::{BufRead, BufReader, Result, Write};
use std::net::TcpListener;

use crate::config::{cli, domain};

fn listener() -> Result<String> {
    let listener = TcpListener::bind("127.0.0.1:8080")?;
    listener.set_nonblocking(false).expect("out of service");

    let (client, address) = listener.accept()?;
    println!("connect client:{}", address);

    let mut socket = client.try_clone()?;
    let mut reader = BufReader::new(client);
    let mut recv_data = String::new();
    let v = reader.read_line(&mut recv_data)?;
    if v > 0 {
        println!("server receive {}", recv_data);
        let response = String::from(format!("client recv {}", recv_data)).into_bytes();
        match socket.write_all(&response) {
            Ok(()) => println!("client response success"),
            Err(v) => println!("client response failed:{}", v),
        };
    };
    return Ok("ok".to_string());
}

fn main() {
    let args = cli::cli_options();
    let config = domain::get_config(args);
    println!("{:?}", config);
    println!("Hello {}!", config.username);
    let _ = listener();
}
