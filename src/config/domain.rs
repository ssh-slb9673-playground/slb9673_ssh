use crate::config::cli;
use std::{env, path::PathBuf};

#[derive(Debug)]
pub struct Config {
    pub username: String,
    pub remote_address: String,
    pub port: u32,
    pub privatekey_filepath: PathBuf,
}

impl Config {
    fn new(args: cli::Args) -> Config {
        let privatekey_filepath = env::home_dir().unwrap().join(".ssh/id_rsa");
        Config {
            username: args.name,
            remote_address: args.addr,
            port: 22,
            privatekey_filepath,
        }
    }
}

pub fn get_config(args: cli::Args) -> Config {
    Config::new(args)
}
