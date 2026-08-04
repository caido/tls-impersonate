#![allow(dead_code)]
#[macro_use]
mod macros;

pub mod alpn;
mod compress;
pub mod options;

#[cfg(test)]
mod tests {
    use boring::ssl::ConnectConfiguration;
    use bytes::BytesMut;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };

    use crate::options::TlsOptions;

    #[tokio::test]
    async fn client() -> Result<(), Box<dyn std::error::Error>> {
        let profiles = [
            TlsOptions::chrome(),
            TlsOptions::chrome_124(),
            TlsOptions::chrome_132(),
            TlsOptions::firefox(),
            TlsOptions::opera(),
            TlsOptions::safari(),
        ];
        for profile in profiles {
            let cfg = ConnectConfiguration::try_from(&profile)?;
            let stream = TcpStream::connect("tls.peet.ws:443").await?;
            let mut tls = tokio_boring::connect(cfg, "tls.peet.ws", stream).await?;
            let req = b"GET /api/all HTTP/1.1\r\n\
                   Host: tls.peet.ws\r\n\r\n";
            tls.write_all(req).await?;
            let mut buf = BytesMut::new();
            loop {
                let size = tls.read_buf(&mut buf).await?;
                if size == 0 {
                    break;
                }
            }
            println!("{}", String::from_utf8_lossy(&buf));
            println!("====");
        }
        Ok(())
    }
}
