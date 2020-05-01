//!# Rust DTLS
//! A Datagram TLS implementation using ring.
//!
//! `Rust DTLS` is a pure rust implementation of DTLS 1.2.
//!
//! It is intended to provide DTLS without OpenSSL.
//!

#[macro_use]
extern crate enum_primitive_derive;
extern crate num_traits;

mod alert;
mod change_cipher_spec;
mod cipher;
pub mod client;
mod crypto;
mod datagram;
mod dtls;
mod errors;
mod extensions;
mod fields;
mod flight;
mod fragment;
mod handshake;
mod handshaker;
mod pack;
mod record;
mod session;
//mod state;
mod test;
pub mod transport {
    pub mod transport;
    pub mod udp;
}
