mod config;

use crate::config::Config;

use anyhow::{anyhow, Result};
use clap::Parser;
use tokio::io;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

const CHUNK_SIZE: usize = 1024;

#[derive(Debug, Parser)]
#[clap(author, version)]
pub struct Args {
    #[clap(short, long)]
    pub config: String,
}

async fn proxy(config: &Config) -> io::Result<()> {
    let listener = TcpListener::bind(&config.inbound.address).await?;
    log::info!("Listening {}", config.inbound.address);

    loop {
        let (conn, _) = listener.accept().await?;
        let upstream = TcpStream::connect(&config.outbound.address).await?;

        let (mut reader, mut writer) = conn.into_split();
        let (mut ureader, mut uwriter) = upstream.into_split();

        let mut buf = [0; CHUNK_SIZE];

        tokio::spawn(async move {
            loop {
                let length = match reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(x) => x,
                    _ => break,
                };

                match uwriter.write_all(&buf[..length]).await {
                    Ok(_) => log::info!("written {} bytes to upstream", length),
                    _ => break,
                }
            }
        });

        tokio::spawn(async move {
            loop {
                let length = match ureader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(x) => x,
                    _ => break,
                };

                match writer.write_all(&buf[..length]).await {
                    Ok(_) => log::info!("written {} bytes to local", length),
                    _ => break,
                }
            }
        });
    }
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

    match proxy(&config).await {
        Err(e) => Err(anyhow!("{}", e)),
        _ => Ok(()),
    }

    // let listener = TcpListener::bind("127.0.0.1:1090").await?;
    // println!("listening :9099");

    // loop {
    //     let (client, _) = listener.accept().await?;
    //     let server = TcpStream::connect("127.0.0.1:10809").await?;

    //     let (mut inread, mut inwriter) = client.into_split();
    //     let (mut outread, mut outwriter) = server.into_split();

    //     let mut buf = [0; 1024];

    //     tokio::spawn(async move {
    //         loop {
    //             let len = match inread.read(&mut buf).await {
    //                 Ok(0) => {
    //                     println!("read 0 bytes and should break");
    //                     break;
    //                 },
    //                 Ok(x) => x,
    //                 _ => break,
    //             };
    //             println!("read {} ", String::from_utf8_lossy(&buf));
    //             match outwriter.write_all(&buf[..len]).await {
    //                 Ok(_) => println!("write {} data", len),
    //                 _ => break,
    //             };
    //         }
    //     });

    //     tokio::spawn(async move {
    //         loop {
    //             let len = match outread.read(&mut buf).await {
    //                 Ok(0) => break,
    //                 Ok(x) => x,
    //                 _ => break,
    //             };
    //             println!("read {} bytes", len);
    //             match inwriter.write_all(&buf[..len]).await {
    //                 Ok(_) => println!("write {} data", len),
    //                 _ => break,
    //             }
    //         }
    //     });
    // }
}
