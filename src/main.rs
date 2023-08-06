mod config;
mod crypto;
mod network;
mod protocol;
mod utils;

use crate::{
    config::{cli, domain},
    protocol::ssh_server::SshServer,
};

fn main() {
    let args = cli::cli_options();
    let config = domain::get_config(args);
    println!("{:?}", config);

    let server = SshServer::new(config.remote_address, config.username).unwrap();
    server.connection_setup_client();
}
