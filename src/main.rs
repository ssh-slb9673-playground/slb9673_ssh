mod config;
mod crypto;
mod network;
mod protocol;
mod utils;

use crate::config::{cli, domain};
use crate::protocol::client::SshClient;

fn main() {
    let args = cli::cli_options();
    let config = domain::get_config(args);
    println!("{:?}", config);

    let mut client = SshClient::new(config.remote_address, config.username).unwrap();
    client.connection_setup();
}
