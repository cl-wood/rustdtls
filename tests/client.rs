extern crate dtls;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::{Command, Stdio};
use std::{thread, time};

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

    // Give server time to probably receive msg, then kill it and check
    thread::sleep(time::Duration::from_secs(1));

    let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
    let udp_transport = dtls::transport::udp::Udp::new(socket_addr, "127.0.0.1:0").expect("failed to create udp transport");

    let mut client = dtls::client::Client::new(&udp_transport).expect("failed to create client");
    client.send_client_hello().expect("failed to send ClientHello");
    client.recv_hello_verify_request().expect("failed to receive HelloVerifyRequest");
    client.send_client_hello().expect("failed to send ClientHello with cookie");
    client.recv_flight_4().expect("recv flight 4 failed");
    client.send_flight_5().expect("send flight 5 failed");
    client.recv_flight_6().expect("recv flight 6 failed");

    thread::sleep(time::Duration::from_secs(1));

    server.kill().expect("server cannot be killed");
}
