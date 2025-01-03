use std::pin::Pin;

use tls_impersonate::TlsSettings;
use tls_impersonate_openssl::OpensslConnector;
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio_openssl::SslStream;

pub async fn connect<A: ToSocketAddrs>(addr: A, domain: &str, settings: TlsSettings) {
    // Connect to mock server
    let stream = TcpStream::connect(addr).await.unwrap();

    // Prepare ssl
    let connector = OpensslConnector::new(&settings.into()).unwrap();
    let configuration = connector.configure().unwrap();
    let ssl = configuration.into_ssl(domain).unwrap();
    let mut stream = SslStream::new(ssl, stream).unwrap();

    // Connect
    let res = Pin::new(&mut stream).connect().await;
    assert!(res.is_err());
}

pub async fn connect2<A: ToSocketAddrs>(
    addr: A,
    domain: &str,
    settings: TlsSettings,
) -> SslStream<TcpStream> {
    // Connect to mock server
    let stream = TcpStream::connect(addr).await.unwrap();

    // Prepare ssl
    let connector = OpensslConnector::new(&settings.into()).unwrap();
    let configuration = connector.configure().unwrap();
    let ssl = configuration.into_ssl(domain).unwrap();
    let mut stream = SslStream::new(ssl, stream).unwrap();

    // Connect
    Pin::new(&mut stream).connect().await.unwrap();

    stream
}
