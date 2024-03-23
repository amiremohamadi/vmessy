use crate::utils::{extract_addr, Addr, Aes128CfbDec, Aes128CfbEnc};

use std::marker::Unpin;
use std::time::{SystemTime, UNIX_EPOCH};

use aes::cipher::{AsyncStreamCipher, KeyInit, KeyIvInit};
use aes_gcm::{
    aead::{Aead, Payload},
    Aes128Gcm,
};

use const_fnv1a_hash::fnv1a_hash_32;
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};

use rand::Rng;
use sha2::Sha256;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, Result},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
};

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
    aead: bool,
}

impl Vmess {
    pub fn new(stream: TcpStream, uuid: [u8; 16], aead: bool) -> Self {
        Self {
            uuid,
            aead,
            stream: Some(stream),
        }
    }

    pub fn into_split(self) -> (VmessReader<OwnedReadHalf>, VmessWriter<OwnedWriteHalf>) {
        let stream = self.stream.expect("stream should contain a value");
        let (reader, writer) = stream.into_split();
        let encoder = Encoder::new();

        let r = VmessReader {
            reader,
            encoder,
            aead: self.aead,
        };
        let w = VmessWriter {
            encoder,
            writer,
            uuid: self.uuid,
            handshaked: false,
            aead: self.aead,
        };

        (r, w)
    }
}

pub struct VmessReader<R: AsyncRead + Unpin> {
    reader: R,
    encoder: Encoder,
    aead: bool,
}

impl<R: AsyncRead + Unpin> VmessReader<R> {
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.aead {
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
            let mut decoder = Aes128CfbDec::new(&key.into(), &iv.into());

            let mut header = [0u8; 4];
            self.reader.read_exact(&mut header).await?;
            decoder.decrypt(&mut header); // ignore the header for now
                                          // just decrypt it because our decoder is stateful

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
            let mut length = [0u8; 2];
            self.reader.read_exact(&mut length).await?;
            decoder.decrypt(&mut length);

            // When Opt(M) is enabled, the value of L is equal to the true value xor Mask
            // Mask = (RequestMask.NextByte() << 8) + RequestMask.NextByte()
            let length = (length[0] as usize) << 8 | (length[1] as usize) - 4; // 4bytes checksum

            let mut checksum = [0u8; 4];
            self.reader.read(&mut checksum).await?;
            decoder.decrypt(&mut checksum); // ignore the checksum for now
                                            // just decrypt it because our decoder is stateful

            self.reader.read(&mut buf[..length]).await?;
            decoder.decrypt(&mut buf[..length]);

            Ok(length)
        } else {
            let key = &sha256!(&self.encoder.key)[..16];
            let iv = &sha256!(&self.encoder.iv)[..16];

            let length_key = &crate::hash::kdf(&key, &[b"AEAD Resp Header Len Key"])[..16];
            let length_iv = &crate::hash::kdf(&iv, &[b"AEAD Resp Header Len IV"])[..12];

            let mut header_length = [0u8; 18];
            self.reader.read_exact(&mut header_length).await?;

            // header length
            let length = Aes128Gcm::new(length_key.into())
                .decrypt(length_iv.into(), &header_length[..])
                .unwrap();
            let length = ((length[0] as u16) << 8) | (length[1] as u16) + 16; // TODO: document

            let mut header = vec![0u8; length as usize];
            self.reader.read_exact(&mut header).await?; // ignore the header for now

            // read next 2bytes to retrive the payload length
            let mut length = [0u8; 2];
            self.reader.read(&mut length).await?;
            let length = ((length[0] as usize) << 8) | (length[1] as usize);

            self.reader.read(&mut buf[..length]).await
        }
    }
}

pub struct VmessWriter<W: AsyncWrite + Unpin> {
    pub(crate) writer: W,
    pub(crate) encoder: Encoder,
    pub(crate) uuid: [u8; 16],
    pub(crate) handshaked: bool,
    pub(crate) aead: bool,
}

impl<W: AsyncWrite + Unpin> VmessWriter<W> {
    async fn handshake<'a>(&mut self, addr: Addr<'a>) -> Result<()> {
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

        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap() // safe to unwrap: always later than UNIX_EPOCH
            .as_secs()
            .to_be_bytes();

        if !self.aead {
            let mut hash = <Hmac<Md5> as KeyInit>::new_from_slice(&self.uuid).unwrap(); // safe to unwrap: always valid length.
            hash.update(&time);
            let auth = hash.finalize().into_bytes();
            self.writer.write_all(&auth).await?;
        }

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

        let enc_method = if !self.aead {
            0x00 // AES-128-CFB
        } else {
            0x05 // None
        };
        cmd.extend_from_slice(&[
            0x00,       // Response Authentication Value
            0x01,       // Option S(0x01): Standard format data stream (recommended)
            enc_method, // 4bits Reserved + Encryption Method
            0x00,       // 1byte Reserved
            0x01,       // Command: 0x01 TCP
        ]);

        // TODO: extract port from request. for now we use 80 for all requests
        cmd.extend_from_slice(&addr.port().to_be_bytes()); // Port

        // TODO: support ipv4/ipv6. for now we just support domain name
        cmd.extend_from_slice(&[0x02]); // Address Type: Domain name

        let mut address = vec![addr.host().len() as _];
        address.extend_from_slice(addr.host());
        cmd.extend_from_slice(&address);

        // P bytes random value -> assume p = 0, so we don't push data for it

        let checksum = fnv1a_hash_32(&cmd, None);
        cmd.extend_from_slice(&checksum.to_be_bytes()); // 4bytes checksum

        let iv = md5!(&time, &time, &time, &time);
        let key = md5!(&self.uuid, b"c48619fe-8f02-49e0-b9e9-edf763e17e21");

        if !self.aead {
            // Non-AEAD
            // encrypted using AES-128-CFB
            // Key: MD5(user ID + []byte('c48619fe-8f02-49e0-b9e9-edf763e17e21'))
            // IV: MD5(X + X + X + X), X = []byte(time generated by authentication information) (8 bytes, Big Endian)
            Aes128CfbEnc::new(&key.into(), &iv.into()).encrypt(&mut cmd);
            self.writer.write_all(&cmd).await
        } else {
            // AEAD
            let auth_id = self.create_auth_id(&time);

            let mut nonce = [0u8; 8];
            rand::thread_rng().fill(&mut nonce);

            // header length
            let payload = Payload {
                msg: &(cmd.len() as u16).to_be_bytes(),
                aad: &auth_id,
            };
            let header_length_key =
                &crate::hash::kdf(&key, &[b"VMess Header AEAD Key_Length", &auth_id, &nonce])[..16];
            let header_length_nonce =
                &crate::hash::kdf(&key, &[b"VMess Header AEAD Nonce_Length", &auth_id, &nonce])
                    [..12];

            let header_length = Aes128Gcm::new(header_length_key.into())
                .encrypt(header_length_nonce.into(), payload)
                .unwrap(); // TODO: unwrap

            // header payload
            let payload = Payload {
                msg: &cmd,
                aad: &auth_id,
            };
            let header_payload_key =
                &crate::hash::kdf(&key, &[b"VMess Header AEAD Key", &auth_id, &nonce])[..16];
            let header_payload_nonce =
                &crate::hash::kdf(&key, &[b"VMess Header AEAD Nonce", &auth_id, &nonce])[..12];

            let header_payload = Aes128Gcm::new(header_payload_key.into())
                .encrypt(header_payload_nonce.into(), payload)
                .unwrap();

            self.writer.write_all(&auth_id).await?;
            self.writer.write_all(&header_length).await?;
            self.writer.write_all(&nonce).await?;
            self.writer.write_all(&header_payload).await
        }
    }

    pub async fn write(&mut self, buf: &[u8]) -> Result<()> {
        if !self.handshaked {
            let addr = extract_addr(buf)?;
            log::info!("accepted {:?}", addr);

            self.handshake(addr).await?;
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

        let length = buf.len() as u16;
        if !self.aead {
            let checksum = fnv1a_hash_32(&buf, None);

            vmess_buf.extend_from_slice(&(length + 4).to_be_bytes()); // 4bytes fnv1a
            vmess_buf.extend_from_slice(&checksum.to_be_bytes());
            vmess_buf.extend_from_slice(buf);

            Aes128CfbEnc::new(&self.encoder.key.into(), &self.encoder.iv.into())
                .encrypt(&mut vmess_buf);
        } else {
            vmess_buf.extend_from_slice(&length.to_be_bytes());
            vmess_buf.extend_from_slice(buf);
        }

        self.writer.write_all(&vmess_buf).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::Result;

    struct MockWriter {
        written: Vec<u8>,
    }

    impl AsyncWrite for MockWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize>> {
            self.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<()>> {
            todo!()
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<()>> {
            todo!()
        }
    }

    #[tokio::test]
    async fn test_vmess_write() {
        let w = MockWriter { written: vec![] };

        let uuid = [0; 16];
        let encoder = Encoder::new();
        let mut vwriter = VmessWriter {
            writer: w,
            handshaked: false,
            aead: false,
            uuid,
            encoder,
        };

        let buf = b"GET http://google.com/ HTTP/1.1\r\nHost: google.com\r\nUser-Agent: curl/7.85.0";
        let _ = vwriter.write(buf).await;

        assert_eq!(vwriter.handshaked, true);

        let header_length = 72;
        let data = vwriter.writer.written.as_mut_slice();
        Aes128CfbDec::new(&encoder.key.into(), &encoder.iv.into())
            .decrypt(&mut data[header_length..]);

        let payload = &data[header_length..];

        let payload_length = u16::from_be_bytes([payload[0], payload[1]]);
        assert_eq!(payload_length, 78);

        let checksum = fnv1a_hash_32(buf, None);
        assert_eq!(checksum.to_be_bytes(), payload[2..6]);

        // actual data
        assert_eq!(&payload[6..], buf);
    }
}
