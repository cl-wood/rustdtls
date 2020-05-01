use crate::datagram::datagram_to_records;
use crate::dtls::Dtls;
use crate::errors;
use crate::flight;
use crate::handshake;
use crate::record;
use crate::session::Session;
use crate::transport::transport::Transport;

use ring::rand;
use ring::rand::SecureRandom;
use std::io::Write;

pub struct Client<'a> {
    transport: &'a dyn Transport,
    session: Session,
    rand: rand::SystemRandom,
    handshake_complete: bool,
}

/// A DTLS client. Exposes read() and write() methods to send data over the DTLS protocol.
impl<'a> Client<'a> {
    /// Constructs a new `Client`.
    ///
    /// Takes a Transport, like UDP, which handles sending and receiving datagrams.
    ///
    /// # Examples
    /// ```
    /// // Construct a `Client` that uses UDP as the underlying transport to connect to a DTLS server on localhost port 4444
    /// use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 4444);
    /// let udp_transport = dtls::transport::udp::Udp::new(socket_addr, "127.0.0.1:0").expect("failed to create udp transport");
    /// let mut client = dtls::client::Client::new(&udp_transport).expect("failed to create client");
    /// // client.write(b"application data").expect("write application data failed");
    /// ```
    pub fn new(transport: &'a dyn Transport) -> Result<Self, errors::DTLSError> {
        Ok(Self {
            transport,
            session: Session::new(),
            rand: rand::SystemRandom::new(),
            handshake_complete: false,
        })
    }

    ///
    /// Sends `data` to the endpoint specified by `self.transport`.
    ///
    pub fn write(&mut self, data: &[u8]) -> Result<(), errors::DTLSError> {
        if !self.handshake_complete {
            self.handshake()?;
        }
        // TODO will need to buffer writes if they are too large

        match (self.session.security_parameters.as_ref(), self.session.key_block.as_ref()) {
            (Some(security_parameters), Some(key_block)) => {
                let mut iv: [u8; 16] = [0; 16]; // TODO base on security_parameters.cipher_parameters.fixed_iv_length
                let _ = self.rand.fill(&mut iv);

                let application_data = Dtls::application_data(self.session.epoch, self.session.sequence_number, data, security_parameters)?;

                let buf = application_data.encrypt(&iv, &security_parameters, &key_block)?;
                let _ = self.transport.send(buf.as_slice())?;
                Ok(())
            }
            (_, _) => Err(errors::DTLSError::SessionError),
        }
    }

    ///
    /// Receives `data` from the endpoint specified by `self.transport`.
    ///
    /// Returns number of bytes written to `data`.
    ///
    pub fn read(&mut self, mut data: &mut [u8]) -> Result<usize, errors::DTLSError> {
        if !self.handshake_complete {
            self.handshake()?;
        }

        let mut buf = [0; 1500];
        let n = self.transport.recv(&mut buf)?;
        let datagram = &mut buf[..n];
        let records = datagram_to_records(datagram.to_vec());
        if records.len() != 1 {
            return Err(errors::DTLSError::RecordError);
        }

        match (self.session.security_parameters.as_ref(), self.session.key_block.as_ref()) {
            (Some(security_parameters), Some(key_block)) => {
                let application_data =
                    record::DTLSCiphertext::decrypt(&records[0][handshake::APPLICATION_DATA_OFFSET..], security_parameters, key_block)?;
                println!("Application data record: {:x?}", application_data);
                Ok(data.write(&application_data)?)
            }
            _ => Err(errors::DTLSError::SessionError),
        }
    }

    fn handshake(&mut self) -> Result<(), errors::DTLSError> {
        let _ = flight::Flight1::send(self.transport, &self.rand, &mut self.session)?;
        let _ = flight::Flight2::recv(self.transport, &mut self.session)?;
        let _ = flight::Flight3::send(self.transport, &self.rand, &mut self.session)?;
        let _ = flight::Flight4::recv(self.transport, &mut self.session)?;
        let _ = flight::Flight5::send(self.transport, &self.rand, &mut self.session)?;
        let _ = flight::Flight6::recv(self.transport, &mut self.session)?;
        self.handshake_complete = true;
        Ok(())
    }
}
