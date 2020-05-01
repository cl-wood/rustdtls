use crate::crypto;
use crate::fields;
use crate::handshake;
use crate::pack::Pack;
use crate::record;

pub struct Session {
    pub epoch: record::Epoch,
    pub sequence_number: record::SequenceNumber,
    pub message_seq: handshake::MessageSeq,

    pub cookie: handshake::Cookie,

    pub handshake_messages: Vec<u8>,

    pub security_parameters: Option<crypto::SecurityParameters>,
    pub key_block: Option<crypto::KeyBlock>,

    pub client_random: Option<handshake::Random>,
    pub server_random: Option<handshake::Random>,
    pub server_pub_key: Option<Vec<u8>>,
    //server_certificate: Option<x509_parser::x509::X509Certificate>,
    pub expected_server_verify_data: Option<Vec<u8>>,
}

impl Session {
    pub fn new() -> Self {
        Self {
            epoch: fields::Uint16(0),
            sequence_number: fields::Uint48([0; 6]),
            message_seq: fields::Uint16(0),

            cookie: handshake::Cookie::empty(),

            handshake_messages: Vec::new(),

            security_parameters: None,
            key_block: None,
            client_random: None,
            server_random: None,
            server_pub_key: None,
            expected_server_verify_data: None,
        }
    }
}
