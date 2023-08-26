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
    //     .username("anko")
    //     .private_key_path("~/.ssh/id_rsa")
    //     .connect("127.0.0.1:2222")
    //     .unwrap();
    let mut client = SshClient::new(config.remote_address, config.username).unwrap();
    match client.connection_setup() {
        Ok(_) => {}
        Err(e) => println!("error: {}", e),
    };

    let mut client = client.pack_channel();
    client.channel().unwrap();
    client.channel().unwrap();
    client.client_setup();
    // client.shell();
    client.exec("ls -lah".to_string());
}
