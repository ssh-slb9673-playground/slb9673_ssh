mod config;
mod crypto;
mod network;
mod protocol;
pub mod utils;

use crate::config::{cli, domain};
use crate::protocol::client::SshClient;

fn main() {
    let args = cli::cli_options();
    let config = domain::get_config(args);
    println!("{:?}", config);

    // use ssh_rs::ssh;
    // let mut session = ssh::create_session()
    //     .username("ubuntu")
    //     .private_key_path("./id_rsa")
    //     .connect("127.0.0.1:2222")
    //     .unwrap();
    let mut client = SshClient::new(config.remote_address, config.username).unwrap();
    let _ = client.connection_setup().unwrap();
}
