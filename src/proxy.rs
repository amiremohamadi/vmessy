use crate::config::Config;
use crate::vmess::Vmess;

use tokio::io;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

const CHUNK_SIZE: usize = 16384;

macro_rules! copy {
    ($r:ident, $w:ident) => {
        async move {
            let mut buf = [0; CHUNK_SIZE];

            loop {
                let len = match $r.read(&mut buf).await {
                    Ok(x) => {
                        if x == 0 {
                            break;
                        }
                        x
                    }
                    _ => break,
                };

                let _ = $w.write(&buf[..len]).await;
            }
        }
    }
}

pub async fn run(config: &Config) -> io::Result<()> {
    let listener = TcpListener::bind(&config.inbound.address).await?;
    log::info!("Listening {}", config.inbound.address);

    loop {
        let (conn, _) = listener.accept().await?;

        let upstream = TcpStream::connect(&config.outbound.address).await?;
        let mut vmess = Vmess::new(upstream, *config.outbound.uuid.as_bytes());

        let (mut reader, mut writer) = conn.into_split();
        let (mut ureader, mut uwriter) = vmess.into_split();

        tokio::spawn(copy!(reader, uwriter));
        // let mut buf = [0; CHUNK_SIZE];
        // tokio::spawn(async move {
        //     loop {
        //         let len = match reader.read(&mut buf).await {
        //             Ok(x) => {
        //                 if x == 0 {
        //                     break;
        //                 }
        //                 x
        //             }
        //             _ => break,
        //         };

        //         uwriter.write(&buf[..len]).await;
        //     }
        // });

        tokio::spawn(async move {
            let mut buf2 = [0; CHUNK_SIZE];
            loop {
                let len = match ureader.read(&mut buf2).await {
                    Ok(0) => break,
                    Ok(x) => x,
                    _ => break,
                };


                // println!("read {:?}", &buf2[..len]);
                // let _ = writer.write_all(&buf2[..len]).await;
            }
        });
    }
}
