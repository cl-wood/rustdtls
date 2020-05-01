use crate::cipher;
use crate::crypto::{create_verify_data, ephemeral_keys, shared_secret, ConnectionEnd, HandshakeParameters, KeyBlock, SecurityParameters};
use crate::datagram::datagram_to_records;
use crate::dtls::Dtls;
use crate::errors;
use crate::fields::{increment_uint16, increment_uint48, Uint16, Uint48};
use crate::fragment::reassemble_handshake;
use crate::handshake::*;
use crate::pack::Pack;
use crate::record::{epoch_from_record, sequence_number_from_record, ContentType, DTLSCiphertext, DTLSPlaintext, Epoch, SequenceNumber};
use crate::session::Session;
use crate::transport::transport::Transport;

use ring::rand;
use ring::rand::SecureRandom;
use std::collections::BTreeMap;

#[derive(Debug, Copy, Clone)]
struct FlightMessage {
    required: bool,
    r#type: ContentType,
    handshake_type: Option<HandshakeType>,
}

// TODO once working on server, create flight trait with send/recv

pub struct Flight1 {}
impl<'a> Flight1 {
    pub fn send(transport: &dyn Transport, rand: &rand::SystemRandom, mut session: &'a mut Session) -> Result<&'a Session, errors::DTLSError> {
        let msg = Dtls::client_hello(rand, session.cookie.clone(), session.message_seq, session.epoch, session.sequence_number)?;
        let buf = msg.pack();
        let _ = transport.send(buf.as_slice())?;

        session.sequence_number = increment_uint48(session.sequence_number);
        session.message_seq = increment_uint16(session.message_seq);
        session.client_random = Some(msg.fragment.body.random);
        Ok(session)
    }
}

pub struct Flight2 {}
impl<'a> Flight2 {
    pub fn recv(transport: &dyn Transport, mut session: &'a mut Session) -> Result<&'a mut Session, errors::DTLSError> {
        let mut buf = [0; 1500]; // TODO size seems imprecise, max length datagrams are probably too large here
        let n = transport.recv(&mut buf)?;
        let buf = &mut buf[..n];
        let mut hello_verify_request = DTLSPlaintext::<HelloVerifyRequest>::empty();
        let _ = hello_verify_request.unpack(&mut buf.to_vec())?;
        session.cookie = hello_verify_request.fragment.body.cookie;
        Ok(session)
    }
}

pub struct Flight3 {}
impl<'a> Flight3 {
    // Flight 1, 3
    pub fn send(transport: &dyn Transport, rand: &rand::SystemRandom, mut session: &'a mut Session) -> Result<&'a mut Session, errors::DTLSError> {
        let msg = Dtls::client_hello(rand, session.cookie.clone(), session.message_seq, session.epoch, session.sequence_number)?;
        let buf = msg.pack();
        let _ = transport.send(buf.as_slice())?;
        session.sequence_number = increment_uint48(session.sequence_number);
        session.message_seq = increment_uint16(session.message_seq);
        session.client_random = Some(msg.fragment.body.random); // TODO one of this or flight 1's is a duplicate, remove
        session.handshake_messages.extend_from_slice(&msg.fragment.pack());
        Ok(session)
    }
}

pub struct Flight4 {}
impl<'a> Flight4 {
    pub fn recv(transport: &dyn Transport, mut session: &'a mut Session) -> Result<&'a mut Session, errors::DTLSError> {
        let mut has_flight = false;
        let mut fragments: BTreeMap<(Epoch, SequenceNumber, MessageSeq), Vec<u8>> = BTreeMap::new();

        // Poll until we receive the entire flight or TODO we timeout
        while !has_flight {
            let mut buf = [0; 1500];
            let n = transport.recv(&mut buf)?;
            let datagram = &mut buf[..n];
            let records = datagram_to_records(datagram.to_vec());
            // if datagram contains record with ServerDone, verify we have all the other records and continue
            for record in records {
                let id = (
                    epoch_from_record(record.clone()),
                    sequence_number_from_record(record.clone())?,
                    message_seq_from_record(record.clone())?,
                );
                fragments.insert(id, record.clone());
            }

            has_flight = have_flight_4(fragments.clone())?;
        }

        let mut sequence: Vec<MessageSeq> = fragments.keys().map(|(_, _, ms)| *ms).collect();
        sequence.dedup();

        let v: BTreeMap<(Epoch, SequenceNumber, MessageSeq), Vec<u8>> = fragments.clone().into_iter().filter(|e| (e.0).2 == sequence[0]).collect();
        let mut server_hello = Handshake::<ServerHelloExtended>::empty();
        let reassembled_server_hello = reassemble_handshake(v)?;
        let _ = server_hello.unpack(&mut reassembled_server_hello.clone()); // TODO better error
        session.handshake_messages.extend_from_slice(&reassembled_server_hello);
        assert_eq!(reassembled_server_hello.len(), server_hello.pack().len());

        session.server_random = Some(server_hello.body.server_hello.random.clone());

        let v: BTreeMap<(Epoch, SequenceNumber, MessageSeq), Vec<u8>> = fragments.clone().into_iter().filter(|e| (e.0).2 == sequence[1]).collect();
        let mut certificates = Handshake::<Certificates>::empty();
        let reassembled_certificates = reassemble_handshake(v)?;
        let _ = certificates.unpack(&mut reassembled_certificates.clone());
        session.handshake_messages.extend_from_slice(&reassembled_certificates);
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

        let v: BTreeMap<(Epoch, SequenceNumber, MessageSeq), Vec<u8>> = fragments.clone().into_iter().filter(|e| (e.0).2 == sequence[2]).collect();
        let mut server_key_exchange = Handshake::<ServerKeyExchangeExtended>::empty();
        let reassembled_server_key_exchange = reassemble_handshake(v)?;
        let _ = server_key_exchange.unpack(&mut reassembled_server_key_exchange.clone());
        session.handshake_messages.extend_from_slice(&reassembled_server_key_exchange);
        assert_eq!(reassembled_server_key_exchange.len(), server_key_exchange.pack().len());

        session.server_pub_key = Some(server_key_exchange.body.pubkey);
        let v: BTreeMap<(Epoch, SequenceNumber, MessageSeq), Vec<u8>> = fragments.into_iter().filter(|e| (e.0).2 == sequence[3]).collect();
        let mut server_hello_done = Handshake::<ServerHelloDone>::empty();
        let reassembled_server_hello_done = reassemble_handshake(v)?;
        let _ = server_hello_done.unpack(&mut reassembled_server_hello_done.clone());
        session.handshake_messages.extend_from_slice(&reassembled_server_hello_done);
        assert_eq!(reassembled_server_hello_done.len(), server_hello_done.pack().len());

        Ok(session)
    }
}

const FLIGHT_4: &[FlightMessage] = &[
    FlightMessage {
        required: true,
        r#type: ContentType::Handshake,
        handshake_type: Some(HandshakeType::ServerHello),
    },
    FlightMessage {
        required: false,
        r#type: ContentType::Handshake,
        handshake_type: Some(HandshakeType::Certificates),
    },
    FlightMessage {
        required: false,
        r#type: ContentType::Handshake,
        handshake_type: Some(HandshakeType::ServerKeyExchange),
    },
    //FlightMessage{required: false, r#type: record::ContentType::Handshake, handshake_type: Some(handshake::HandshakeType::CertificateRequest)}, // TODO not supported
    FlightMessage {
        required: true,
        r#type: ContentType::Handshake,
        handshake_type: Some(HandshakeType::ServerHelloDone),
    },
];

pub struct Flight5 {}
impl<'a> Flight5 {
    pub fn send(transport: &dyn Transport, rand: &rand::SystemRandom, mut session: &'a mut Session) -> Result<&'a mut Session, errors::DTLSError> {
        let (our_pub_key, our_priv_key) = ephemeral_keys()?; // TODO make keys based on cipher

        let msg = Dtls::client_key_exchange(session.message_seq, session.epoch, session.sequence_number, &our_pub_key)?;
        let buf = msg.pack();
        let _ = transport.send(buf.as_slice())?;

        session.sequence_number = increment_uint48(session.sequence_number);
        session.message_seq = increment_uint16(session.message_seq);
        session.handshake_messages.extend_from_slice(&msg.fragment.pack());
        let shared_secret = shared_secret(our_priv_key, &session.server_pub_key.as_ref().unwrap())?;

        match (session.client_random, session.server_random) {
            (Some(client_random), Some(server_random)) => {
                let handshake_parameters = HandshakeParameters::new(&shared_secret, client_random, server_random)?;
                let security_parameters = SecurityParameters::new(
                    ConnectionEnd::Client,
                    cipher::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, // TODO get this from server's message
                    CompressionMethod::Null,                    // TODO same as above
                    handshake_parameters,
                )?;
                session.key_block = Some(KeyBlock::new(security_parameters.clone())?);
                session.security_parameters = Some(security_parameters);
            }
            _ => return Err(errors::DTLSError::SessionError),
        }

        let msg = Dtls::change_cipher_spec(session.epoch, session.sequence_number)?;
        let buf = msg.pack();
        let _ = transport.send(buf.as_slice())?;

        session.epoch = increment_uint16(session.epoch);
        session.sequence_number = Uint48([0; 6]);

        match (
            session.security_parameters.as_ref(),
            session.key_block.as_ref(),
            session.client_random,
            session.server_random,
        ) {
            (Some(security_parameters), Some(key_block), Some(client_random), Some(server_random)) => {
                let verify_data = create_verify_data(
                    &shared_secret,
                    client_random,
                    server_random,
                    CLIENT_FINISHED_LABEL,
                    session.handshake_messages.clone(),
                )?;

                let mut iv: [u8; 16] = [0; 16]; // TODO base on security_parameters.cipher_parameters.fixed_iv_length
                let _ = rand.fill(&mut iv);

                let finished = Dtls::finished(
                    session.message_seq,
                    session.epoch,
                    session.sequence_number,
                    verify_data,
                    &security_parameters.clone(),
                    &key_block.clone(),
                )?;

                let buf = finished.encrypt(&iv, &security_parameters, &key_block)?;
                let _ = transport.send(buf.as_slice())?;

                // TODO ugly but it works for finished in this ciphersuite b/c we don't include the 8 7's as padding
                println!("Finished: {:x?}", &finished.fragment.pack()[..&finished.fragment.pack().len() - 8]);
                session.sequence_number = increment_uint48(session.sequence_number);
                session
                    .handshake_messages
                    .extend_from_slice(&finished.fragment.pack()[..&finished.fragment.pack().len() - 8]);

                session.expected_server_verify_data = Some(create_verify_data(
                    &shared_secret,
                    client_random,
                    server_random,
                    SERVER_FINISHED_LABEL,
                    session.handshake_messages.clone(),
                )?);
                Ok(session)
            }
            _ => Err(errors::DTLSError::SessionError),
        }
    }
}

pub struct Flight6 {}
impl<'a> Flight6 {
    // Receive server's ChangeCipherSpec, Finished
    pub fn recv(transport: &dyn Transport, mut session: &'a mut Session) -> Result<&'a mut Session, errors::DTLSError> {
        let mut has_flight = false;
        let mut fragments: BTreeMap<(Epoch, SequenceNumber, MessageSeq), Vec<u8>> = BTreeMap::new();

        // Poll until we receive the entire flight or TODO we timeout
        while !has_flight {
            let mut buf = [0; 1500];
            let n = transport.recv(&mut buf)?;
            let datagram = &mut buf[..n];
            let records = datagram_to_records(datagram.to_vec());

            for record in records {
                let id = (
                    epoch_from_record(record.clone()),
                    sequence_number_from_record(record.clone())?,
                    message_seq_from_record(record.clone())?,
                );
                fragments.insert(id, record.clone());
            }
            has_flight = have_flight_6(fragments.clone())?;
        }
        // TODO checks for flight?
        // TODO check ChangeCipherSpec

        let mut epochs: Vec<MessageSeq> = fragments.keys().map(|(e, _, _)| *e).collect();
        epochs.dedup();

        if epochs.len() != 2 {
            return Err(errors::DTLSError::FlightLengthError);
        }

        // epochs[1] has epoch of Finished
        // get the fragments with epoch 1, if len isnt 1 return an error
        let v: BTreeMap<(Epoch, SequenceNumber, MessageSeq), Vec<u8>> =
            fragments.into_iter().filter(|((epoch, _, _), _)| epoch == &epochs[1]).collect();

        let encrypted_finished = reassemble_handshake(v)?;

        // Decrypt and verify Finished
        match (
            session.security_parameters.as_ref(),
            session.key_block.as_ref(),
            session.expected_server_verify_data.as_ref(),
        ) {
            (Some(security_parameters), Some(key_block), Some(expected_server_verify_data)) => {
                let finished = DTLSCiphertext::decrypt(&encrypted_finished, security_parameters, key_block)?;
                let expected_verify_data = expected_server_verify_data.clone();
                let expected_finished = Dtls::finished(
                    Uint16(session.message_seq.0 + 2),
                    session.epoch,
                    session.sequence_number,
                    expected_verify_data,
                    &security_parameters.clone(),
                    &key_block.clone(),
                )?;
                if finished != expected_finished.fragment.pack() {
                    return Err(errors::DTLSError::IntegrityError("server finished does not match expectations"));
                }

                // TODO check MAC

                Ok(session)
            }
            _ => Err(errors::DTLSError::SessionError),
        }
    }
}

const FLIGHT_6: &[FlightMessage] = &[
    FlightMessage {
        required: true,
        r#type: ContentType::ChangeCipherSpec,
        handshake_type: None,
    },
    FlightMessage {
        required: true,
        r#type: ContentType::Handshake,
        handshake_type: Some(HandshakeType::Finished),
    },
];

pub fn have_flight_4(fragments: BTreeMap<(Epoch, SequenceNumber, MessageSeq), Vec<u8>>) -> Result<bool, errors::DTLSError> {
    have_flight(fragments, FLIGHT_4)
}

pub fn have_flight_6(fragments: BTreeMap<(Epoch, SequenceNumber, MessageSeq), Vec<u8>>) -> Result<bool, errors::DTLSError> {
    have_flight(fragments, FLIGHT_6)
}

// TODO parse_flight. after all epoch+seq_nums gotten, try to parse, this will fail if they aren't in order

fn have_flight(
    fragments: BTreeMap<(Epoch, SequenceNumber, MessageSeq), Vec<u8>>,
    flight_messages: &[FlightMessage],
) -> Result<bool, errors::DTLSError> {
    for message in flight_messages.into_iter().filter(|m| m.required) {
        let mut has_message = false;
        for (_, fragment) in &fragments {
            let content_type = content_type_from_record(fragment.clone())?;
            if content_type == message.r#type {
                match content_type {
                    ContentType::ChangeCipherSpec => has_message = true,
                    ContentType::Handshake if handshake_type_from_record(fragment.clone()) == message.handshake_type => has_message = true,
                    ContentType::Handshake if message.handshake_type == Some(HandshakeType::Finished) => has_message = true,
                    _ => (),
                }
            }
        }
        if !has_message {
            return Ok(false);
        }
    }

    let mut keys = fragments.keys();
    match keys.next() {
        None => Ok(false),
        Some((epoch, seq_num, _)) => {
            let mut prev_epoch = epoch;
            let mut prev_seq_num = seq_num;
            while let Some((epoch, seq_num, _)) = keys.next() {
                // Either (A) epoch is same, seq_num is +1, or (B) epoch is +1, seq_num is 0
                if (epoch != prev_epoch || seq_num != &increment_uint48(*prev_seq_num))
                    && (epoch != &increment_uint16(*prev_epoch) || seq_num != &Uint48([0; 6]))
                {
                    return Ok(false);
                }
                prev_epoch = epoch;
                prev_seq_num = seq_num;
            }
            Ok(true)
        }
    }
}
