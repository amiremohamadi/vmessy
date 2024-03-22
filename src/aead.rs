use crate::vmess::VmessWriter;
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use md5::{Digest, Md5};
use rand::Rng;
use tokio::io::AsyncWrite;

impl<W: AsyncWrite + Unpin> VmessWriter<W> {
    pub(crate) fn create_auth_id(&self, time: &[u8; 8]) -> [u8; 16] {
        let mut buf = [0u8; 16];

        buf[..8].copy_from_slice(time);

        let mut salt = [0u8; 4];
        rand::thread_rng().fill(&mut salt);
        buf[8..12].copy_from_slice(&salt);

        let crc = crc32fast::hash(&buf[..12]);
        buf[12..].copy_from_slice(&crc.to_be_bytes());

        let key = md5!(&self.uuid, b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
        let key = crate::hash::kdf(&key, &[b"AES Auth ID Encryption"]);
        let cipher = Aes128::new((&key[..16]).into());

        let mut b = GenericArray::from([0u8; 16]);
        cipher.encrypt_block_b2b(&buf.into(), &mut b);

        b.into()
    }
}
