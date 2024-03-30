mod config;
mod crypto;
mod network;
mod protocol;
pub mod utils;

use crate::{
    config::{cli_options, get_config},
    protocol::client::SessionBuilder,
};

fn main() -> anyhow::Result<()> {
    let args = cli_options();
    let config = get_config(args);
    println!("{:?}", config);

    let mut client = SessionBuilder::create_session()
        .username(&config.username)
        .private_key_path("~/.ssh/id_rsa")
        .connect(config.remote_address)?;
    let mut client = client.pack_channel();

    let _ = client.client_setup();
    // let _ = client.shell();
    let _ = client.exec("ps aux".to_string());
    let _ = client.exec("ls -lah".to_string());

    Ok(())
}
