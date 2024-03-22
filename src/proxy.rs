use crate::{config::Config, copy, vmess::Vmess};

use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

pub async fn run(config: &Config) -> io::Result<()> {
    let listener = TcpListener::bind(&config.inbound.address).await?;
    log::info!("Listening {}", config.inbound.address);

    loop {
        let (conn, _) = listener.accept().await?;

        let upstream = TcpStream::connect(&config.outbound.address).await?;
        let vmess = Vmess::new(
            upstream,
            *config.outbound.uuid.as_bytes(),
            config.outbound.aead,
        );

        let (mut reader, mut writer) = conn.into_split();
        let (mut ureader, mut uwriter) = vmess.into_split();

        tokio::spawn(copy!(reader, uwriter));
        tokio::spawn(copy!(ureader, writer));
    }
}
