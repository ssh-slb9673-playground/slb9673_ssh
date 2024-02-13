mod config;
mod crypto;
mod network;
mod protocol;
pub mod utils;

use crate::config::{cli, domain};
use crate::protocol::client::SessionBuilder;
use anyhow::Result;

fn main() -> Result<()> {
    let args = cli::cli_options();
    let config = domain::get_config(args);
    println!("{:?}", config);

    // use ssh_rs::ssh;
    // let mut session = ssh::create_session()
    //     .username("anko")
    //     .private_key_path("~/.ssh/id_rsa")
    //     .connect("127.0.0.1:2222")
    //     .unwrap();
    let mut client = SessionBuilder::create_session()
        .username(&config.username)
        .private_key_path("~/.ssh/id_rsa")
        .connect(config.remote_address)?;
    client.connection_setup()?;

    let mut client = client.pack_channel();
    let _ = client.client_setup();
    let _ = client.exec("ls -lah".to_string());

    Ok(())
}
