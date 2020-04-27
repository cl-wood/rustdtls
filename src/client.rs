use crate::cipher;
use crate::crypto;
use crate::datagram::datagram_to_records;
use crate::dtls;
use crate::errors;
use crate::fields;
use crate::flight;
use crate::fragment;
use crate::handshake;
use crate::pack::Pack;
use crate::record;
use crate::transport::transport::Transport;

use ring::rand::SecureRandom;
use std::collections::BTreeMap;

pub struct Client<'a> {
    transport: &'a dyn Transport,
    dtls: dtls::Dtls,
    cookie: handshake::Cookie,

    epoch: record::Epoch,
    sequence_number: record::SequenceNumber,
    message_seq: handshake::MessageSeq,
    handshake_messages: Vec<u8>,

    security_parameters: Option<crypto::SecurityParameters>,
    key_block: Option<crypto::KeyBlock>,

    client_random: Option<handshake::Random>,
    server_random: Option<handshake::Random>,
    server_pub_key: Option<Vec<u8>>,
    //server_certificate: Option<x509_parser::x509::X509Certificate>,
}

impl<'a> Client<'a> {
    pub fn new(transport: &dyn Transport) -> Result<Client, errors::DTLSError> {
        Ok(Client {
            transport,
            dtls: dtls::Dtls::new(),
            cookie: handshake::Cookie::empty(),
            epoch: fields::Uint16(0),
            sequence_number: fields::Uint48([0; 6]),
            message_seq: fields::Uint16(0),
            handshake_messages: Vec::new(),
            security_parameters: None,
            key_block: None,
            client_random: None,
            server_random: None,
            server_pub_key: None,
        })
    }

    // Flight 1, 3
    pub fn send_client_hello(&mut self) -> Result<(), errors::DTLSError> {
        let msg = self
            .dtls
            .client_hello(self.cookie.clone(), self.message_seq, self.epoch, self.sequence_number)?;

        let buf = msg.pack();
        let _ = self.transport.send(buf.as_slice())?;
        self.sequence_number = fields::increment_uint48(self.sequence_number); // STATE CHANGE
        self.message_seq = fields::increment_uint16(self.message_seq); // STATE CHANGE

        // Don't include initial ClientHello if doing cookie exchange?
        if self.cookie.length.0 > 0 {
            self.handshake_messages.extend_from_slice(&msg.fragment.pack()); // STATE CHANGE
        }
        self.client_random = Some(msg.fragment.body.random);

        Ok(())
    }

    // Receive Flight 2
    pub fn recv_hello_verify_request(&mut self) -> Result<(), errors::DTLSError> {
        let mut buf = [0; 1500]; // TODO size seems imprecise, max length datagrams are probably too large here
        let n = self.transport.recv(&mut buf)?;
        let buf = &mut buf[..n];

        let mut hello_verify_request = record::DTLSPlaintext::<handshake::HelloVerifyRequest>::empty();
        let _ = hello_verify_request.unpack(&mut buf.to_vec())?;

        self.cookie = hello_verify_request.fragment.body.cookie; // STATE CHANGE
        Ok(())
    }

    // Receive Flight 4
    pub fn recv_flight_4(&mut self) -> Result<(), errors::DTLSError> {
        let mut has_flight = false;
        let mut fragments: BTreeMap<(record::Epoch, record::SequenceNumber, handshake::MessageSeq), Vec<u8>> = BTreeMap::new();

        // Poll until we receive the entire flight or TODO we timeout
        while !has_flight {
            let mut buf = [0; 1500];
            let n = self.transport.recv(&mut buf)?;
            let datagram = &mut buf[..n];
            let records = datagram_to_records(datagram.to_vec());
            // if datagram contains record with ServerDone, verify we have all the other records and continue
            for record in records {
                let id = (
                    record::epoch_from_record(record.clone()),
                    record::sequence_number_from_record(record.clone())?,
                    handshake::message_seq_from_record(record.clone()),
                );
                fragments.insert(id, record.clone());
            }

            has_flight = flight::have_flight(fragments.clone())?;
        }

        // TODO test this
        let mut sequence: Vec<handshake::MessageSeq> = fragments.keys().map(|(_, _, ms)| *ms).collect();
        sequence.dedup();

        let v: BTreeMap<(record::Epoch, record::SequenceNumber, handshake::MessageSeq), Vec<u8>> =
            fragments.clone().into_iter().filter(|e| (e.0).2 == sequence[0]).collect();
        let mut server_hello = handshake::Handshake::<handshake::ServerHelloExtended>::empty();
        let reassembled_server_hello = fragment::reassemble_handshake(v)?;
        let _ = server_hello.unpack(&mut reassembled_server_hello.clone()); // TODO better error
        self.handshake_messages.extend_from_slice(&reassembled_server_hello); // STATE CHANGE
        assert_eq!(reassembled_server_hello.len(), server_hello.pack().len());

        self.server_random = Some(server_hello.body.server_hello.random.clone()); // STATE CHANGE

        let v: BTreeMap<(record::Epoch, record::SequenceNumber, handshake::MessageSeq), Vec<u8>> =
            fragments.clone().into_iter().filter(|e| (e.0).2 == sequence[1]).collect();
        let mut certificates = handshake::Handshake::<handshake::Certificates>::empty();
        let reassembled_certificates = fragment::reassemble_handshake(v)?;
        let _ = certificates.unpack(&mut reassembled_certificates.clone());
        self.handshake_messages.extend_from_slice(&reassembled_certificates); // STATE CHANGE
        assert_eq!(reassembled_certificates.len(), certificates.pack().len());

        /* not needed yet, this is for Auth
        let res = parse_x509_der(&certificates.fragment.body.certificates[0].certificate[..]);
        match res {
            Ok((rem, cert)) => {
                assert!(rem.is_empty());
                assert_eq!(cert.tbs_certificate.version, 2);
                //let x = cert.tbs_certificate.subject_pki.subject_public_key.data; // last 3 are e
                self.server_pub_key = Some(cert.tbs_certificate.subject_pki.subject_public_key.data.to_vec());
                println!("CERT : {:x?}", self.server_pub_key);

            },
            _ => panic!("x509 parsing failed: {:?}", res),
        }*/

        let v: BTreeMap<(record::Epoch, record::SequenceNumber, handshake::MessageSeq), Vec<u8>> =
            fragments.clone().into_iter().filter(|e| (e.0).2 == sequence[2]).collect();
        let mut server_key_exchange = handshake::Handshake::<handshake::ServerKeyExchangeExtended>::empty();
        let reassembled_server_key_exchange = fragment::reassemble_handshake(v)?;
        let _ = server_key_exchange.unpack(&mut reassembled_server_key_exchange.clone());
        self.handshake_messages.extend_from_slice(&reassembled_server_key_exchange); // STATE CHANGE
        assert_eq!(reassembled_server_key_exchange.len(), server_key_exchange.pack().len());

        self.server_pub_key = Some(server_key_exchange.body.pubkey);
        let v: BTreeMap<(record::Epoch, record::SequenceNumber, handshake::MessageSeq), Vec<u8>> =
            fragments.into_iter().filter(|e| (e.0).2 == sequence[3]).collect();
        let mut server_hello_done = handshake::Handshake::<handshake::ServerHelloDone>::empty();
        let reassembled_server_hello_done = fragment::reassemble_handshake(v)?;
        let _ = server_hello_done.unpack(&mut reassembled_server_hello_done.clone());
        self.handshake_messages.extend_from_slice(&reassembled_server_hello_done); // STATE CHANGE
        assert_eq!(reassembled_server_hello_done.len(), server_hello_done.pack().len());

        Ok(())
    }

    // Send ClientKeyExchange, ChangeCipherSpec, Finished
    pub fn send_flight_5(&mut self) -> Result<usize, errors::DTLSError> {
        let (our_pub_key, our_priv_key) = crypto::ephemeral_keys()?; // TODO make keys based on cipher

        let msg = self
            .dtls
            .client_key_exchange(self.message_seq, self.epoch, self.sequence_number, &our_pub_key)?;
        let buf = msg.pack();
        let _ = self.transport.send(buf.as_slice())?;

        /* BEGIN STATE CHANGE */
        self.sequence_number = fields::increment_uint48(self.sequence_number);
        self.message_seq = fields::increment_uint16(self.message_seq);
        self.handshake_messages.extend_from_slice(&msg.fragment.pack());
        let shared_secret = crypto::shared_secret(our_priv_key, &self.server_pub_key.as_ref().unwrap())?;

        match (self.client_random, self.server_random) {
            (Some(client_random), Some(server_random)) => {
                let handshake_parameters = crypto::HandshakeParameters::new(&shared_secret, client_random, server_random)?;
                let security_parameters = crypto::SecurityParameters::new(
                    crypto::ConnectionEnd::Client,
                    cipher::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, // TODO get this from server's message
                    handshake::CompressionMethod::Null,         // TODO same as above
                    handshake_parameters,
                );
                self.key_block = Some(crypto::KeyBlock::new(security_parameters.clone())?);
                self.security_parameters = Some(security_parameters);
            }
            _ => println!("TODO panic or something!"),
        }
        /* END STATE CHANGE */

        let msg = self.dtls.change_cipher_spec(self.epoch, self.sequence_number)?;
        let buf = msg.pack();
        let _ = self.transport.send(buf.as_slice())?;

        /* BEGIN STATE CHANGE */
        self.epoch = fields::increment_uint16(self.epoch);
        self.sequence_number = fields::Uint48([0; 6]); // new sequence for new epoch
                                                       /* END STATE CHANGE */

        match (
            self.security_parameters.as_ref(),
            self.key_block.as_ref(),
            self.client_random,
            self.server_random,
        ) {
            (Some(security_parameters), Some(key_block), Some(client_random), Some(server_random)) => {
                let verify_data = crypto::create_verify_data(
                    &shared_secret,
                    client_random,
                    server_random,
                    handshake::CLIENT_FINISHED_LABEL,
                    self.handshake_messages.clone(),
                )?;

                let mut iv: [u8; 16] = [0; 16]; // TODO base on security_parameters.cipher_parameters.fixed_iv_length
                let _ = self.dtls.rand.fill(&mut iv);

                let finished = self.dtls.finished(
                    self.message_seq,
                    self.epoch,
                    self.sequence_number,
                    verify_data,
                    &security_parameters.clone(),
                    &key_block.clone(),
                )?;

                let buf = finished.encrypt(&iv, &security_parameters, &key_block)?;
                let _ = self.transport.send(buf.as_slice())?;
            }
            _ => println!("TODO panic or something!"),
        }

        Ok(0)
    }

    // Receive server's ChangeCipherSpec, Finished
    pub fn recv_flight_6(&mut self) -> Result<(), errors::DTLSError> {
        let mut has_flight = false;
        let mut fragments: BTreeMap<(record::Epoch, record::SequenceNumber), Vec<u8>> = BTreeMap::new();

        // Poll until we receive the entire flight or TODO we timeout
        while !has_flight {
            let mut buf = [0; 1500];
            let n = self.transport.recv(&mut buf)?;
            let datagram = &mut buf[..n];
            let records = datagram_to_records(datagram.to_vec());

            for record in records {
                let id = (
                    record::epoch_from_record(record.clone()),
                    record::sequence_number_from_record(record.clone())?,
                );
                fragments.insert(id, record.clone());
            }
            has_flight = flight::have_flight_6(fragments.clone())?;
        }

        Ok(())
    }
}

// TODO pass slice instead of Vec for all these functions so we can pass the same Vec to multiple functions, or use Bytes?
