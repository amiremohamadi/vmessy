use vmessy::{config::Config, proxy};

use anyhow::{anyhow, Result};
use clap::Parser;

#[derive(Debug, Parser)]
#[clap(author, version)]
pub struct Args {
    #[clap(short, long)]
    pub config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::formatted_builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    let args = Args::parse();

    let config = match std::fs::read_to_string(args.config) {
        Ok(c) => Config::new(&c),
        _ => panic!("could not find the file"),
    }?;

    match proxy::run(&config).await {
        Err(e) => Err(anyhow!("{}", e)),
        _ => Ok(()),
    }
}
