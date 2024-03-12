use std::marker::Unpin;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncWrite, AsyncRead, AsyncWriteExt, AsyncReadExt, Result};
use tokio::net::{
    TcpStream,
    tcp::{OwnedReadHalf, OwnedWriteHalf}
};
use rand::Rng;
use hmac::{Hmac, Mac};
use md5::{Md5, Digest};
use aes::cipher::{AsyncStreamCipher, KeyIvInit};
use const_fnv1a_hash::fnv1a_hash_32;

type Aes128CfbEnc = cfb_mode::Encryptor<aes::Aes128>;
type Aes128CfbDec = cfb_mode::Decryptor<aes::Aes128>;


macro_rules! md5 {
    ( $($v:expr ),+) => {
        {
            let mut hash = Md5::new();
            $(
                hash.update($v);
            )*

            hash.finalize()
        }
    }
}

#[derive(Clone, Copy)]
pub struct Encoder {
    pub iv: [u8; 16],
    pub key: [u8; 16],
}

impl Encoder {
    pub fn new() -> Self {
        let mut key = [0u8; 16];
        let mut iv = [0u8; 16];

        rand::thread_rng().fill(&mut key);
        rand::thread_rng().fill(&mut iv);

        Self { iv, key }
    }
}

pub struct Vmess {
    stream: Option<TcpStream>,
    uuid: [u8; 16],
}

impl Vmess {
    pub fn new(stream: TcpStream, uuid: [u8; 16]) -> Self {
        let encoder = Encoder::new();

        Self {
            uuid,
            stream: Some(stream),
        }
    }

    pub fn into_split(self) -> (VmessReader<OwnedReadHalf>, VmessWriter<OwnedWriteHalf>) {
        let stream = self.stream.expect("stream should contain a value");
        let (reader, writer) = stream.into_split();
        let encoder = Encoder::new();

        let r = VmessReader { reader, encoder };
        let w = VmessWriter {
            encoder,
            writer,
            uuid: self.uuid,
            handshaked: false,
        };

        (r, w)
    }
}

pub struct VmessReader<R: AsyncRead + Unpin> {
    reader: R,
    encoder: Encoder,
}

impl<R: AsyncRead + Unpin> VmessReader<R> {
    pub async fn read(&mut self, mut buf: &mut [u8]) -> Result<usize> {
        // The header data is encrypted using AES-128-CFB encryption
        // The IV is MD5 of the data encryption IV, and the Key is MD5 of the data encryption Key
        //
        // +---------------------------+------------+-------------+------------------+-----------------+----------------------+
        // |          1 Byte           |   1 Byte   |   1 Byte    |      1 Byte      |     M Bytes     |    Remaining Part    |
        // +---------------------------+------------+-------------+------------------+-----------------+----------------------+
        // | Response Authentication V | Option Opt | Command Cmd | Command Length M | Command Content | Actual Response Data |
        // +---------------------------+------------+-------------+------------------+-----------------+----------------------+

        let key = md5!(&self.encoder.key);
        let iv = md5!(&self.encoder.iv);
        let mut buffer = [0u8; 64];
        self.reader.read(&mut buffer).await?;
        Aes128CfbDec::new(&key.into(), &iv.into()).decrypt(&mut buffer);
        // Aes128CfbEnc::new(&key.into(), &iv.into()).encrypt(&mut buffer);

        println!("data {:?}", &buffer);

        Ok(0)
    }
}

pub struct VmessWriter<W: AsyncWrite + Unpin> {
    writer: W,
    encoder: Encoder,
    uuid: [u8; 16],
    handshaked: bool,
}

impl<W: AsyncWrite + Unpin> VmessWriter<W> {
    async fn handshake(&mut self) -> Result<()> {
        // https://xtls.github.io/en/development/protocols/vmess.html#authentication-information
        //
        // +----------------------------+
        // |          16 Bytes          |
        // +----------------------------+
        // | Authentication Information |
        // +----------------------------+
        //
        // H = MD5
        // K = User ID (16 bytes)
        // M = UTC time accurate to seconds, with a random value of ±30 seconds from the current time (8 bytes, Big Endian)
        // Hash = HMAC(H, K, M)

        let time = SystemTime::now().duration_since(UNIX_EPOCH)
            .unwrap() // safe to unwrap: always later than UNIX_EPOCH
            .as_secs().to_be_bytes();

        let mut hash = Hmac::<Md5>::new_from_slice(&self.uuid)
            .unwrap(); // safe to unwrap: always valid length
        hash.update(&time);

        let auth = hash.finalize().into_bytes();
        self.writer.write_all(&auth).await?;

        // https://xtls.github.io/en/development/protocols/vmess.html#command-section
        //
        // +---------+--------------------+---------------------+-------------------------------+---------+----------+-------------------+----------+---------+---------+--------------+---------+--------------+----------+
        // | 1 Byte  |      16 Bytes      |      16 Bytes       |            1 Byte             | 1 Byte  |  4 bits  |      4 bits       |  1 Byte  | 1 Byte  | 2 Bytes |    1 Byte    | N Bytes |   P Bytes    | 4 Bytes  |
        // +---------+--------------------+---------------------+-------------------------------+---------+----------+-------------------+----------+---------+---------+--------------+---------+--------------+----------+
        // | Version | Data Encryption IV | Data Encryption Key | Response Authentication Value | Options | Reserved | Encryption Method | Reserved | Command | Port    | Address Type | Address | Random Value | Checksum |
        // +---------+--------------------+---------------------+-------------------------------+---------+----------+-------------------+----------+---------+---------+--------------+---------+--------------+----------+

        let mut cmd = vec![0x1u8]; // version is always 1

        cmd.extend_from_slice(&self.encoder.iv); // Data Encryption IV
        cmd.extend_from_slice(&self.encoder.key); // Data Encryption Key

        cmd.extend_from_slice(&[0x00]); // Response Authentication Value

        cmd.extend_from_slice(&[0x01]); // Option S(0x01): Standard format data stream (recommended)
        cmd.extend_from_slice(&[0x00]); // 4bits Reserved + Encryption Method (0x00 AES-128-CFB)
        cmd.extend_from_slice(&[0x00]); // 1byte Reserved

        cmd.extend_from_slice(&[0x01]); // Command: 0x01 TCP

        cmd.extend_from_slice(&(80u16).to_be_bytes()); // Port

        // cmd.extend_from_slice(&[0x02]); // Address Type: Domain name
        // let domain = "google.com";
        // let mut address = vec![domain.len() as _];
        // address.extend_from_slice(domain.as_bytes());
        // cmd.extend_from_slice(&address); // Address

        cmd.extend_from_slice(&[0x01]);
        cmd.extend_from_slice(&[216, 239, 38, 120]);

        // P bytes random value -> assume p = 0, so we don't push data for it

        let checksum = fnv1a_hash_32(&cmd, None);
        cmd.extend_from_slice(&checksum.to_be_bytes()); // 4bytes checksum

        // encrypted using AES-128-CFB
        // Key: MD5(user ID + []byte('c48619fe-8f02-49e0-b9e9-edf763e17e21'))
        // IV: MD5(X + X + X + X), X = []byte(time generated by authentication information) (8 bytes, Big Endian)
        let iv = md5!(&time, &time, &time, &time);
        let key = md5!(&self.uuid, b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
        Aes128CfbEnc::new(&key.into(), &iv.into()).encrypt(&mut cmd);

        self.writer.write_all(&cmd).await
    }


    pub async fn write(&mut self, buf: &[u8]) -> Result<()> {
        if !self.handshaked {
            self.handshake().await?;
            self.handshaked = true;
        }

        // https://xtls.github.io/en/development/protocols/vmess.html#data-section
        //
        // +----------+-------------+
        // | 2 Bytes  |   L Bytes   |
        // +----------+-------------+
        // | Length L | Data Packet |
        // +----------+-------------+
        //
        // - Length L: A big-endian integer with a maximum value of 2^14
        // - Packet: A data packet encrypted by the specified encryption method

        // AES-128-CFB:
        // The entire data section is encrypted using AES-128-CFB
        // - 4 bytes: FNV1a hash of actual data
        // - L - 4 bytes: actual data
        let mut vmess_buf = Vec::new();
        {
            let length = buf.len() as u16 + 4;
            let checksum = fnv1a_hash_32(&buf, None);

            vmess_buf.extend_from_slice(&length.to_be_bytes());
            vmess_buf.extend_from_slice(&checksum.to_be_bytes());
            vmess_buf.extend_from_slice(buf);
        }

        Aes128CfbEnc::new(
            &self.encoder.key.into(),
            &self.encoder.iv.into()).encrypt(&mut vmess_buf);

        self.writer.write_all(&vmess_buf).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::Error;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    struct MockWriter { written: Vec<u8> }

    impl AsyncWrite for MockWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8]
        ) -> Poll<Result<usize, Error>> {
            self.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _: &mut Context<'_>
        ) -> Poll<Result<(), Error>> { todo!() }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _: &mut Context<'_>
        ) -> Poll<Result<(), Error>> { todo!() }
    }

    #[tokio::test]
    async fn test_vmess_write() {
        let mut w = MockWriter { written: vec![] };

        let _ = write(&mut w, &[1, 2]).await;
        assert_eq!(w.written, vec![1, 2]);

    }
}
