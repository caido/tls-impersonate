use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::bail;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

pub struct MockServer {
    token: CancellationToken,
    addr: SocketAddr,
    last_ja4: Arc<Mutex<Option<String>>>,
}

impl MockServer {
    pub async fn start() -> Self {
        let token = CancellationToken::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let last_ja4 = Arc::new(Mutex::new(None));

        tokio::spawn(log(acceptor_task(
            listener,
            last_ja4.clone(),
            token.child_token(),
        )));

        Self {
            token,
            addr,
            last_ja4,
        }
    }

    pub fn addr(&self) -> &SocketAddr {
        &self.addr
    }

    pub fn last_ja4(&self) -> Option<String> {
        self.last_ja4.lock().clone()
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.token.cancel();
    }
}

#[derive(Debug)]
struct ClientHello {
    tls_version: u16,
    cipher_suites: Vec<u16>,
    extensions: Vec<Extension>,
    alpn_protocols: Vec<String>,
    has_sni: bool,
}

#[derive(Debug)]
struct Extension {
    ext_type: u16,
    #[allow(dead_code)]
    data: Vec<u8>,
}

async fn acceptor_task(
    listener: TcpListener,
    last_ja4: Arc<Mutex<Option<String>>>,
    token: CancellationToken,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
          Ok((stream, _)) = listener.accept() => {
              tokio::spawn(log(receiver_task(stream, last_ja4.clone(), token.child_token())));
          }
          _ = token.cancelled() => {
              break
          }
        }
    }
    Ok(())
}

async fn receiver_task(
    mut stream: TcpStream,
    last_ja4: Arc<Mutex<Option<String>>>,
    token: CancellationToken,
) -> anyhow::Result<()> {
    let mut buffer = [0; 4096];

    tokio::select! {
        res = stream.read(&mut buffer) => {
            match res {
                Ok(_) => {
                    if buffer.starts_with(b"\x16\x03") {
                    let client_hello = parse_client_hello(&buffer);
                    let ja4 = compute_ja4(&client_hello);

                    *last_ja4.lock() = Some(ja4);
                }
                }
                Err(_) => bail!("Not a client hello"),
            }
        }
        _ = token.cancelled() => {
            bail!("Cancelled")
        }
    }

    Ok(())
}

pub async fn log(future: impl Future<Output = anyhow::Result<()>>) {
    if let Err(e) = future.await {
        println!("Target task failed: {:?}", e);
    }
}

fn parse_client_hello(data: &[u8]) -> ClientHello {
    let mut pos = 9; // Skip record layer and handshake header

    // Get TLS version
    let tls_version = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    // Skip random
    pos += 32;

    // Skip session ID
    let session_id_length = data[pos] as usize;
    pos += 1 + session_id_length;

    // Get cipher suites
    let cipher_suites_length = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    let mut cipher_suites = Vec::new();
    for i in (0..cipher_suites_length).step_by(2) {
        cipher_suites.push(u16::from_be_bytes([data[pos + i], data[pos + i + 1]]));
    }
    pos += cipher_suites_length;

    // Skip compression methods
    let compression_methods_length = data[pos] as usize;
    pos += 1 + compression_methods_length;

    // Parse extensions
    let extensions_length = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    let mut extensions = Vec::new();
    let mut alpn_protocols = Vec::new();
    let mut has_sni = false;
    let end_pos = pos + extensions_length;

    while pos < end_pos {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        let ext_length = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        match ext_type {
            0 => has_sni = true,
            16 => {
                // ALPN
                let alpn_length = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                let mut alpn_pos = pos + 2;
                while alpn_pos < pos + 2 + alpn_length {
                    let proto_len = data[alpn_pos] as usize;
                    let proto =
                        String::from_utf8_lossy(&data[alpn_pos + 1..alpn_pos + 1 + proto_len])
                            .to_string();
                    alpn_protocols.push(proto);
                    alpn_pos += 1 + proto_len;
                }
            }
            _ => (),
        }

        extensions.push(Extension {
            ext_type,
            data: data[pos..pos + ext_length].to_vec(),
        });

        pos += ext_length;
    }

    ClientHello {
        tls_version,
        cipher_suites,
        extensions,
        alpn_protocols,
        has_sni,
    }
}

fn compute_ja4(hello: &ClientHello) -> String {
    // Filter GREASE values from cipher suites
    let cipher_suites: Vec<_> = hello
        .cipher_suites
        .iter()
        .filter(|&&cs| (cs & 0x0F0F) != 0x0A0A)
        .collect();

    // Hash cipher suites
    let mut cipher_hex: Vec<_> = cipher_suites
        .iter()
        .map(|&cs| format!("{:04x}", cs))
        .collect();
    cipher_hex.sort();
    let cipher_str = cipher_hex.join(",");
    let c_hash = if cipher_hex.is_empty() {
        "000000000000".to_string()
    } else {
        let mut hasher = Sha256::new();
        hasher.update(cipher_str.as_bytes());
        format!("{:.12x}", hasher.finalize())
    };

    // Filter and hash extensions
    let mut ext_types: Vec<_> = hello
        .extensions
        .iter()
        .filter(|ext| ext.ext_type != 0 && ext.ext_type != 16 && (ext.ext_type & 0x0F0F) != 0x0A0A)
        .map(|ext| format!("{:04x}", ext.ext_type))
        .collect();
    ext_types.sort();
    let ext_str = ext_types.join(",");
    let e_hash = if ext_types.is_empty() {
        "000000000000".to_string()
    } else {
        let mut hasher = Sha256::new();
        hasher.update(ext_str.as_bytes());
        format!("{:.12x}", hasher.finalize())
    };

    // Get ALPN identifier
    let alpn_id = if hello.alpn_protocols.is_empty() {
        "00".to_string()
    } else {
        let proto = &hello.alpn_protocols[0];
        let alpn_chars: Vec<_> = proto.chars().filter(|c| c.is_alphanumeric()).collect();
        if alpn_chars.is_empty() {
            format!("{:02x}", proto.as_bytes()[0])
        } else if alpn_chars.len() == 1 {
            format!("{}{}", alpn_chars[0], alpn_chars[0])
        } else {
            format!("{}{}", alpn_chars[0], alpn_chars[alpn_chars.len() - 1])
        }
    };

    // Build JA4 string
    format!(
        "t{}{}{:02}{:02}{}_{}_{}",
        if hello.tls_version == 0x0303 {
            "13"
        } else {
            "12"
        },
        if hello.has_sni { "d" } else { "i" },
        cipher_suites.len(),
        hello.extensions.len(),
        alpn_id,
        c_hash,
        e_hash
    )
}
