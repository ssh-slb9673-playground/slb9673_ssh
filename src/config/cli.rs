use clap::Parser;

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
