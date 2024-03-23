use std::fmt;
use tokio::io::{Error, ErrorKind, Result};

pub type Aes128CfbEnc = cfb_mode::Encryptor<aes::Aes128>;
pub type Aes128CfbDec = cfb_mode::BufDecryptor<aes::Aes128>;

#[macro_export]
macro_rules! copy {
    ($r:ident, $w:ident) => {
        async move {
            let mut buf = [0; 16384]; // TODO: optimized chunk size

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
    };
}

macro_rules! sha256 {
    ( $($v:expr),+ ) => {
        {
            let mut hash = Sha256::new();
            $(
                hash.update($v);
            )*
            hash.finalize()
        }
    }
}

macro_rules! md5 {
    ( $($v:expr),+ ) => {
        {
            let mut hash = Md5::new();
            $(
                hash.update($v);
            )*
            hash.finalize()
        }
    }
}

pub(crate) struct Addr<'a> {
    host: Option<&'a [u8]>,
    port: Option<u16>,
}

impl<'a> fmt::Debug for Addr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut addr = vec![];

        if let Some(host) = self.host {
            addr.extend_from_slice(host);
        }

        if let Some(port) = self.port {
            addr.extend_from_slice(b":");
            addr.extend_from_slice(&port.to_string().as_bytes());
        }

        write!(f, "{:?}", addr)
    }
}

impl<'a> Addr<'a> {
    pub(crate) fn host(&self) -> &'a [u8] {
        self.host.unwrap_or_default()
    }

    pub(crate) fn port(&self) -> u16 {
        self.port.unwrap_or(80)
    }
}

pub(crate) fn extract_addr<'a>(buf: &'a [u8]) -> Result<Addr<'a>> {
    let header = &[72, 111, 115, 116, 58, 32]; // "Host: "

    let mut addr = Addr {
        host: None,
        port: None,
    };

    let mut start = buf
        .windows(header.len())
        .position(|w| w == header)
        .map(|x| x + header.len())
        .ok_or(Error::new(ErrorKind::Other, "could not extract address"))?;

    let offset = buf[start..]
        .iter()
        .position(|&x| x == b'\r')
        .ok_or(Error::new(ErrorKind::Other, "could not extract address"))?;

    let port_offset = buf[start..start + offset].iter().position(|&x| x == b':');
    if let Some(port_offset) = port_offset {
        addr.host = Some(&buf[start..start + port_offset]);

        let end = start + offset;
        start += port_offset + 1; // skip colon
        let port = String::from_utf8_lossy(&buf[start..end]);
        addr.port = u16::from_str_radix(&port, 10).ok();
    } else {
        addr.host = Some(&buf[start..start + offset]);
    }

    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_addr() {
        let buf = b"GET http://google.com/ HTTP/1.1\r\nHost: google.com\r\nUser-Agent: curl/7.85.0";
        let addr = extract_addr(buf).unwrap();
        assert_eq!(addr.host(), b"google.com");
        assert_eq!(addr.port(), 80);

        let buf =
            b"GET http://google.com/ HTTP/1.1\r\nHost: google.com:443\r\nUser-Agent: curl/7.85.0";
        let addr = extract_addr(buf).unwrap();
        assert_eq!(addr.host(), b"google.com");
        assert_eq!(addr.port(), 443);
    }
}
