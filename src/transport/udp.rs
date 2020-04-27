use crate::errors::DTLSError;
use crate::transport::transport::Transport;

use std::net::{SocketAddr, UdpSocket};

pub struct Udp {
    server: SocketAddr,
    socket: UdpSocket,
}

impl Udp {
    pub fn new(server: SocketAddr, client: &str) -> Result<Self, DTLSError> {
        let socket = UdpSocket::bind(client)?;
        Ok(Self { server, socket })
    }
}

impl Transport for Udp {
    fn send(&self, buf: &[u8]) -> Result<(), DTLSError> {
        let _ = self.socket.send_to(buf, self.server)?;
        Ok(())
    }

    fn recv(&self, mut buf: &mut [u8]) -> Result<usize, DTLSError> {
        let (n, _) = self.socket.recv_from(&mut buf)?;
        Ok(n)
    }

    fn datagram_max(&self) -> usize {
        65_507
    }

    fn current_pmtu_estimate(&self) -> Option<usize> {
        None
    }
}
