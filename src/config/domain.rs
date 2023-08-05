use crate::config::cli;
use std::{env, net::SocketAddr, path::PathBuf};

#[derive(Debug)]
pub struct Config {
    pub username: String,
    pub remote_address: SocketAddr,
    pub privatekey_filepath: PathBuf,
}

impl Config {
    fn new(args: cli::Args) -> Config {
        let remote_address = format!("{}:22", args.addr).parse().unwrap();
        let privatekey_filepath = env::home_dir().unwrap().join(".ssh/id_rsa");
        Config {
            username: args.name,
            remote_address,
            privatekey_filepath,
        }
    }
}

pub fn get_config(args: cli::Args) -> Config {
    Config::new(args)
}
