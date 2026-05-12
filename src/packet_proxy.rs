use crate::logger::log_line;
use crate::PacketEncryptConfig;
use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketProxyConfig {
    pub server_ip: String,
    pub server_port: u16,
    pub packet_encrypt: PacketEncryptConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketProxyEndpoint {
    pub ip: String,
    pub port: u16,
}

pub fn auth_xor_from_cipher(cipher: u32, rsa_d: u32, rsa_n: u32) -> u8 {
    let plain = modpow32(cipher as u64, rsa_d as u64, rsa_n as u64);
    (plain % 255 + 1) as u8
}

pub fn start_packet_encrypt_proxy(config: PacketProxyConfig) -> Result<PacketProxyEndpoint> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).context("bind packet encrypt proxy")?;
    let local = listener
        .local_addr()
        .context("read packet proxy local addr")?;
    let endpoint = PacketProxyEndpoint {
        ip: "127.0.0.1".to_string(),
        port: local.port(),
    };

    log_line!(
        "[PacketProxy] listening {}:{} -> {}:{}",
        endpoint.ip,
        endpoint.port,
        config.server_ip,
        config.server_port
    );

    thread::spawn(move || {
        for accepted in listener.incoming() {
            match accepted {
                Ok(game) => {
                    let cfg = config.clone();
                    thread::spawn(move || {
                        if let Err(e) = handle_game_connection(game, cfg) {
                            log_line!("[PacketProxy] connection ended: {e:#}");
                        }
                    });
                }
                Err(e) => {
                    log_line!("[PacketProxy] accept failed: {e:#}");
                    break;
                }
            }
        }
        log_line!("[PacketProxy] listener stopped");
    });

    Ok(endpoint)
}

fn modpow32(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    if modulus == 0 {
        return 0;
    }
    let mut result = 1 % modulus;
    base %= modulus;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exp >>= 1;
    }
    result
}

fn handle_game_connection(mut game: TcpStream, config: PacketProxyConfig) -> Result<()> {
    let server_addr = format!("{}:{}", config.server_ip, config.server_port);
    let mut server = TcpStream::connect(&server_addr)
        .with_context(|| format!("connect real server {server_addr}"))?;
    log_line!("[PacketProxy] game connected; upstream {server_addr}");

    let mut auth = [0u8; 4];
    server
        .read_exact(&mut auth)
        .context("read packet encrypt auth")?;
    let cipher = u32::from_le_bytes(auth);
    let xor = auth_xor_from_cipher(
        cipher,
        config.packet_encrypt.rsa_d,
        config.packet_encrypt.rsa_n,
    );
    log_line!("[PacketProxy] authdata=0x{cipher:08X} xor=0x{xor:02X}");

    let mut server_reader = server.try_clone().context("clone upstream reader")?;
    let mut game_writer = game.try_clone().context("clone game writer")?;
    let server_to_game = thread::spawn(move || {
        let result = std::io::copy(&mut server_reader, &mut game_writer);
        let _ = game_writer.shutdown(Shutdown::Write);
        result
    });

    let client_result = copy_xor(&mut game, &mut server, xor);
    let _ = server.shutdown(Shutdown::Write);
    let _ = server_to_game.join();
    client_result.context("copy encrypted client traffic")?;
    Ok(())
}

fn copy_xor(reader: &mut TcpStream, writer: &mut TcpStream, xor: u8) -> std::io::Result<u64> {
    let mut total = 0u64;
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            return Ok(total);
        }
        for b in &mut buf[..n] {
            *b ^= xor;
        }
        writer.write_all(&buf[..n])?;
        total += n as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn packet_proxy_auth_xor_matches_startup_hook_formula() {
        assert_eq!(auth_xor_from_cipher(42, 1, 1000), 43);
        assert_eq!(auth_xor_from_cipher(254, 1, 1000), 255);
        assert_eq!(auth_xor_from_cipher(255, 1, 1000), 1);
    }

    #[test]
    fn packet_proxy_config_keeps_real_server_and_rsa_key() {
        let cfg = PacketProxyConfig {
            server_ip: "203.0.113.10".to_string(),
            server_port: 7000,
            packet_encrypt: PacketEncryptConfig {
                rsa_d: 17,
                rsa_n: 3233,
            },
        };

        assert_eq!(cfg.server_ip, "203.0.113.10");
        assert_eq!(cfg.server_port, 7000);
        assert_eq!(cfg.packet_encrypt.rsa_d, 17);
        assert_eq!(cfg.packet_encrypt.rsa_n, 3233);
    }

    #[test]
    fn packet_proxy_consumes_auth_and_xors_client_bytes() {
        let upstream_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            let (mut upstream, _) = upstream_listener.accept().unwrap();
            upstream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            upstream.write_all(&42u32.to_le_bytes()).unwrap();
            let mut encrypted = [0u8; 3];
            upstream.read_exact(&mut encrypted).unwrap();
            tx.send(encrypted).unwrap();
            upstream.write_all(b"OK").unwrap();
        });

        let endpoint = start_packet_encrypt_proxy(PacketProxyConfig {
            server_ip: "127.0.0.1".to_string(),
            server_port: upstream_port,
            packet_encrypt: PacketEncryptConfig {
                rsa_d: 1,
                rsa_n: 1000,
            },
        })
        .unwrap();

        let mut game = TcpStream::connect((endpoint.ip.as_str(), endpoint.port)).unwrap();
        game.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        game.write_all(&[1, 2, 3]).unwrap();
        let mut response = [0u8; 2];
        game.read_exact(&mut response).unwrap();

        assert_eq!(&response, b"OK");
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            [1 ^ 43, 2 ^ 43, 3 ^ 43]
        );
    }
}
