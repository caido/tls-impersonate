use tls_impersonate_openssl::client;
use tls_impersonate_test::MockServer;

use crate::prelude::*;

#[tokio::test]
async fn test_curl_7_61_1() {
    let server = MockServer::start().await;
    let settings = client::curl_7_61_1::settings();

    println!("{:?}", settings);

    connect("localhost:443", "localhost", settings).await;

    assert_eq!(
        server.last_ja4().unwrap(),
        "t13d131000_f57a46bbacb6_e7c285222651"
    );
}

#[tokio::test]
async fn test_curl_7_61_1_real() {
    let server = MockServer::start().await;
    let mut settings = client::curl_7_61_1::settings();
    settings.certs_verification = false;

    let stream = connect2("netflix.com:443", "netflix.com", settings).await;

    println!("{:?}", stream.ssl().version2());

    assert_eq!(
        server.last_ja4().unwrap(),
        "t13d131000_f57a46bbacb6_e7c285222651"
    );
}
