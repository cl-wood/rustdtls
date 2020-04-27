# Rust DTLS
A Datagram TLS implementation using ring.

`Rust DTLS` is a pure rust implementation of DTLS 1.2.

It is intended as a drop-in replacement for [udp_dtls](https://docs.rs/udp-dtls/0.1.0/udp_dtls/) that does not rely on OpenSSL.

## Tests
```bash
cargo test
```


## Misc
```bash
# Client
echo blah | ~/openssl/apps/openssl s_client -dtls1_2  -connect 127.0.0.1:4444 -debug -msg -state -cipher ECDHE-RSA-AES256-SHA -state -msg -debug -security_debug_verbose -trace

# Server
~/openssl/apps/openssl s_server -cert server-cert.pem -key server-key.pem -dtls -accept 4444 -state -msg -debug -security_debug_verbose -trace --msgfile test.txt

~/openssl/apps/openssl s_server -cert server-cert.pem -key server-key.pem -dtls -accept 4444 -state -msg -debug -security_debug_verbose -trace -keylogfile keylogfile.txt -msgfile server.txt

```