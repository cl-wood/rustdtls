/*
/// A test with the functionality we want to recreate in pure rust.
///
/// Sends a message over DTLS using OpenSSL on a local port.
#[tokio::test]
async fn legacy_dtls_over_openssl() {
    let mut server = Command::new("openssl")
        .arg("s_server")
        .arg("-cert")
        .arg("server-cert.pem")
        .arg("-key")
        .arg("server-key.pem")
        .arg("-dtls1")
        .arg("-accept")
        .arg("4444")
        .arg("-debug")
        .arg("-msg")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to execute server. Maybe OpenSSL is not installed?");
    let client = Command::new("openssl")
        .arg("s_client")
        .arg("-dtls1")
        .arg("-connect")
        .arg("127.0.0.1:4444")
        .arg("-debug")
        .arg("-msg")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to execute client. Maybe OpenSSL is not installed?");
    let mut stdin = client.stdin.expect("child");
    stdin.write(b"Hello, DTLS!\n").expect("write failed");

    // Give server time to probably receive msg, then kill it and check
    thread::sleep(time::Duration::from_secs(1));
    server.kill().expect("server cannot be killed");

    let mut output = String::new();
    let mut stdout = server.stdout.expect("stdout failed");
    stdout.read_to_string(&mut output).expect("read_to_string failed");

    assert!(output.contains("Hello, DTLS!"));
}
*/
