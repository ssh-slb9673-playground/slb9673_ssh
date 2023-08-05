mod config;
mod protocol;
mod server;

use crate::config::{cli, domain};

fn main() {
    let args = cli::cli_options();
    let config = domain::get_config(args);
    println!("{:?}", config);
    println!("Hello {}!", config.username);
}
