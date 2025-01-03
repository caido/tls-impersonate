use openssl::ssl::SslVersion;
use tls_impersonate_openssl::client;
use tls_impersonate_test::MockServer;

use crate::prelude::*;

#[tokio::test]
async fn test_curl_7_61_1() {
    let server = MockServer::start().await;
    let settings = client::curl_7_61_1::settings(false);

    let res = connect(server.addr(), "localhost", settings).await;
    assert!(res.is_err());

    assert_eq!(
        server.last_ja4().unwrap(),
        "t13d131100_f57a46bbacb6_51c916dac22e", // Perfect is: "t13d131000_f57a46bbacb6_e7c285222651"
    );
}

#[tokio::test]
async fn test_curl_7_61_1_real() {
    let settings = client::curl_7_61_1::settings(true);

    let stream = connect("google.com:443", "google.com", settings)
        .await
        .unwrap();

    let version = stream.ssl().version2().unwrap();
    assert_eq!(version, SslVersion::TLS1_3);
}
