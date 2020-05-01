extern crate dtls;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::{Command, Stdio};
use std::str::from_utf8;
use std::{thread, time};

use std::io::prelude::*;

/// Verify client connections using OpenSSL server.
#[tokio::test]
async fn handshake_with_openssl() {
    let port = 4444;
    let mut server = Command::new("openssl")
        .arg("s_server")
        .arg("-cert")
        .arg("server-cert.pem")
        .arg("-key")
        .arg("server-key.pem")
        .arg("-dtls")
        .arg("-accept")
        .arg(port.to_string())
        .arg("-debug")
        .arg("-msg")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to execute server. Maybe OpenSSL is not installed?");

    let stdin = server.stdin.as_mut().expect("get stdin failed");
    stdin.write(b"Hello, DTLS client!\n").expect("write failed");

    // Give server time to probably receive msg, then kill it and check
    thread::sleep(time::Duration::from_secs(1));

    // Create client, send data
    let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
    let udp_transport = dtls::transport::udp::Udp::new(socket_addr, "127.0.0.1:0").expect("failed to create udp transport");

    let mut client = dtls::client::Client::new(&udp_transport).expect("failed to create client");
    client.write(b"CLIENT DATA").expect("write application data failed");

    // Check expected read data
    let mut buf = [0; 100];
    let n = client.read(&mut buf).expect("read application data failed");
    let buf = &mut buf[..n];
    let input = from_utf8(&buf).expect("string from_utf8 failed");
    assert!(input.contains("Hello, DTLS client!"));

    thread::sleep(time::Duration::from_secs(1));
    server.kill().expect("server cannot be killed");

    // Check expected write data
    let mut output = String::new();
    let mut stdout = server.stdout.expect("stdout failed");
    stdout.read_to_string(&mut output).expect("read_to_string failed");
    assert!(output.contains("CLIENT DATA"));
}
