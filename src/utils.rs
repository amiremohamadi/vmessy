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

// TODO: find port
pub(crate) fn extract_host(buf: &[u8]) -> Result<&[u8]> {
    let header = &[72, 111, 115, 116, 58, 32]; // "Host: "

    let start = buf
        .windows(header.len())
        .position(|w| w == header)
        .map(|x| x + header.len())
        .ok_or(Error::new(ErrorKind::Other, "could not extract the host"))?;

    let offset = buf
        .iter()
        .skip(start)
        .position(|&x| x == b'\r')
        .ok_or(Error::new(ErrorKind::Other, "could not extract the host"))?;

    Ok(&buf[start..start + offset])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_host() {
        let buf = b"GET http://google.com/ HTTP/1.1\r\nHost: google.com\r\nUser-Agent: curl/7.85.0";
        let host = extract_host(buf).unwrap();
        assert_eq!(host, b"google.com");
    }
}
