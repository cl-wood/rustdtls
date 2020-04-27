use crate::errors;
use crate::fields;
use crate::handshake;
use crate::record;

use std::collections::BTreeMap;

// TODO (re)transmissions are handled a flight at a time? have flight objects that encapsulate the desired handshake messages and can send/recv them

/*
pub struct Flight4 {
    server_hello: handshake::ServerHello,
    //certificate: handshake::Certificate,
    //server_key_exchange: handshake::ServerKeyExchange,
    // TODO part of flight? //certificate_request: handshake::CertificateRequest,
    server_hello_done: handshake::ServerHelloDone,
}*/

pub fn have_flight(fragments: BTreeMap<(record::Epoch, record::SequenceNumber, handshake::MessageSeq), Vec<u8>>) -> Result<bool, errors::DTLSError> {
    let mut has_flight = false;
    for (_, fragment) in &fragments {
        let handshake_type = handshake::handshake_type_from_record(fragment.clone()).ok_or_else(|| errors::DTLSError::InvalidHandshakeTypeError)?;
        if handshake_type == handshake::HandshakeType::ServerHelloDone {
            let sequence_len = record::sequence_number_from_record(fragment.clone())?;
            let expected_sequence: Vec<u64> = (1..=fields::uint48_to_u64(sequence_len)).collect();
            let mut sequence: Vec<u64> = fragments.keys().map(|(_, seq_num, _)| fields::uint48_to_u64(*seq_num)).collect();
            sequence.sort();

            let mut unique_epochs: Vec<record::Epoch> = fragments.keys().map(|(epoch, _, _)| *epoch).collect();
            unique_epochs.dedup();

            if sequence == expected_sequence && unique_epochs.len() == 1 {
                has_flight = true;
            }
        }
    }
    Ok(has_flight)
}

// TODO should check that have a ChangeCipherSpec and a Finished. TODO in theory the Finished could be fragmented
pub fn have_flight_6(fragments: BTreeMap<(record::Epoch, record::SequenceNumber), Vec<u8>>) -> Result<bool, errors::DTLSError> {
    let mut has_change_cipher_spec = false;
    let mut has_possible_finished = false;

    for (_, fragment) in &fragments {
        match handshake::content_type_from_record(fragment.clone())? {
            record::ContentType::Handshake => has_possible_finished = true,
            record::ContentType::ChangeCipherSpec => has_change_cipher_spec = true,
            _ => (),
        }
    }
    Ok(has_change_cipher_spec && has_possible_finished)
}
