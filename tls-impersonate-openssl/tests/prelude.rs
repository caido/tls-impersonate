use std::{error::Error, pin::Pin};

use tls_impersonate::TlsSettings;
use tls_impersonate_openssl::{OpensslConnector, OpensslSettings};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio_openssl::SslStream;

pub async fn connect<A: ToSocketAddrs>(
    addr: A,
    domain: &str,
    settings: TlsSettings,
) -> Result<SslStream<TcpStream>, Box<dyn Error>> {
    // Connect to mock server
    let stream = TcpStream::connect(addr).await.unwrap();

    // Prepare ssl
    let settings = OpensslSettings::new(settings).unwrap();
    let connector = OpensslConnector::new(&settings).unwrap();
    let configuration = connector.configure().unwrap();
    let ssl = configuration.into_ssl(domain).unwrap();
    let mut stream = SslStream::new(ssl, stream).unwrap();

    // Connect
    Pin::new(&mut stream).connect().await?;
    Ok(stream)
}
