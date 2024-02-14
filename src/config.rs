use clap::Parser;
use std::{env, net::SocketAddr, path::PathBuf};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(short, long)]
    pub name: String,

    #[arg(short, long)]
    pub addr: String,
}

pub fn cli_options() -> Args {
    Args::parse()
}

#[derive(Debug)]
pub struct Config {
    pub username: String,
    pub remote_address: SocketAddr,
    pub privatekey_filepath: PathBuf,
}

impl Config {
    fn new(args: Args) -> Config {
        let port = 22;
        let remote_address = format!("{}:{}", args.addr, port).parse().unwrap();
        let privatekey_filepath = env::home_dir().unwrap().join(".ssh/id_rsa");
        Config {
            username: args.name,
            remote_address,
            privatekey_filepath,
        }
    }
}

pub fn get_config(args: Args) -> Config {
    Config::new(args)
}

#[test]
fn parse_socketaddr() {
    let address: SocketAddr = "20.27.177.113:22".to_string().parse().unwrap();
    println!("{:?}", address);
}
