use crate::config::Config;

use tokio::io;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

const CHUNK_SIZE: usize = 1024;

pub async fn run(config: &Config) -> io::Result<()> {
    let listener = TcpListener::bind(&config.inbound.address).await?;
    log::info!("Listening {}", config.inbound.address);

    loop {
        let (conn, _) = listener.accept().await?;
        let upstream = TcpStream::connect(&config.outbound.address).await?;

        let (mut reader, mut writer) = conn.into_split();
        let (ureader, uwriter) = upstream.into_split();

        let mut ureader = crate::vmess::VmessReader(ureader);
        let mut uwriter = crate::vmess::VmessWriter(uwriter);

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
