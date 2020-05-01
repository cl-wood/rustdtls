use crate::errors;
use crate::extensions;
use crate::fields;
use crate::pack::Pack;
use crate::record;

use byteorder::{BigEndian, ByteOrder};
use num_traits::FromPrimitive;
use ring::rand::SecureRandom;
use std::convert::TryFrom;
use std::mem::size_of;
use std::num::TryFromIntError;
use std::time::SystemTime;

#[derive(Debug, Copy, Clone, PartialEq, Primitive)]
#[repr(u8)]
pub enum HandshakeType {
    HelloRequest = 0,
    ClientHello = 1,
    ServerHello = 2,
    HelloVerifyRequest = 3,
    Certificates = 11, // made plural because Certificate message is actually a list of Certificates
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20,
}
impl Pack for HandshakeType {
    fn empty() -> Self {
        HandshakeType::HelloRequest
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(*self as u8);
        v
    }

    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        match v.len() {
            0 => Err(errors::DTLSError::InvalidLengthError),
            _ => {
                let rest: Vec<u8> = v.drain(1..).collect();
                *self = Self::from_u8(v[0]).ok_or_else(|| errors::DTLSError::InvalidHandshakeTypeError)?;
                Ok(rest)
            }
        }
    }
}

pub trait ValidMessage {
    fn into_handshake_type() -> HandshakeType;
}
macro_rules! new_handshake_trait {
    ($name: ident) => {
        impl ValidMessage for $name {
            fn into_handshake_type() -> HandshakeType {
                HandshakeType::$name
            }
        }
    };
}
// Ensures we can statically pack/unpack valid Handshake messages
new_handshake_trait!(ClientHello);
new_handshake_trait!(HelloVerifyRequest);
new_handshake_trait!(ServerHello);
new_handshake_trait!(Certificates);
new_handshake_trait!(ServerKeyExchange);
//new_handshake_trait!(CertificateRequest);
new_handshake_trait!(ServerHelloDone);
new_handshake_trait!(ClientKeyExchange);
new_handshake_trait!(Finished);

pub type Length = fields::Uint24;
pub type MessageSeq = fields::Uint16;
pub type FragmentOffset = fields::Uint24;
pub type FragmentLength = fields::Uint24;

pub const CONTENT_TYPE_OFFSET: usize = 0;
pub const PROTOCOL_VERSION_OFFSET: usize = CONTENT_TYPE_OFFSET + size_of::<record::ContentType>();
pub const EPOCH_OFFSET: usize = PROTOCOL_VERSION_OFFSET + size_of::<record::ProtocolVersion>();
pub const SEQUENCE_NUMBER_OFFSET: usize = EPOCH_OFFSET + size_of::<record::Epoch>();
pub const RECORD_LENGTH_OFFSET: usize = SEQUENCE_NUMBER_OFFSET + size_of::<record::SequenceNumber>();
pub const HANDSHAKE_TYPE_OFFSET: usize = RECORD_LENGTH_OFFSET + size_of::<record::Length>();
pub const HANDSHAKE_LENGTH_OFFSET: usize = HANDSHAKE_TYPE_OFFSET + size_of::<HandshakeType>();
pub const MESSAGE_SEQ_OFFSET: usize = HANDSHAKE_LENGTH_OFFSET + size_of::<Length>();
pub const FRAGMENT_OFFSET_OFFSET: usize = MESSAGE_SEQ_OFFSET + size_of::<MessageSeq>();
pub const FRAGMENT_LENGTH_OFFSET: usize = FRAGMENT_OFFSET_OFFSET + size_of::<FragmentOffset>();
pub const HANDSHAKE_BODY_OFFSET: usize = FRAGMENT_LENGTH_OFFSET + size_of::<FragmentLength>();

pub const APPLICATION_DATA_OFFSET: usize = HANDSHAKE_TYPE_OFFSET;

// TODO, move these into record, remove "from record", operate on &[u8]s
pub fn content_type_from_record(record: Vec<u8>) -> Result<record::ContentType, errors::DTLSError> {
    let mut content_type = record::ContentType::empty();
    let mut x = record[CONTENT_TYPE_OFFSET..CONTENT_TYPE_OFFSET + size_of::<record::ContentType>()].to_vec();
    let _ = content_type.unpack(&mut x)?;
    Ok(content_type)
}

pub fn epoch_from_record(record: Vec<u8>) -> Result<record::Epoch, errors::DTLSError> {
    Ok(fields::Uint16(BigEndian::read_u16(
        &record[EPOCH_OFFSET..EPOCH_OFFSET + size_of::<record::Epoch>()],
    )))
}

pub fn sequence_number_from_record(record: Vec<u8>) -> Result<record::SequenceNumber, errors::DTLSError> {
    let mut seq_num = record::SequenceNumber::empty();
    let mut x = record[SEQUENCE_NUMBER_OFFSET..SEQUENCE_NUMBER_OFFSET + size_of::<record::SequenceNumber>()].to_vec();
    let _ = seq_num.unpack(&mut x)?;
    Ok(seq_num)
}

#[allow(dead_code)]
pub fn record_length_from_record(record: Vec<u8>) -> Result<record::Length, errors::DTLSError> {
    let mut length = record::Length::empty();
    let mut x = record[RECORD_LENGTH_OFFSET..RECORD_LENGTH_OFFSET + size_of::<record::Length>()].to_vec();
    let _ = length.unpack(&mut x)?;
    Ok(length)
}

pub fn handshake_type_from_record(record: Vec<u8>) -> Option<HandshakeType> {
    let handshake_type = HandshakeType::from_u8(record[HANDSHAKE_TYPE_OFFSET])?;
    Some(handshake_type)
}

pub fn handshake_length_from_record(record: Vec<u8>) -> Result<Length, errors::DTLSError> {
    let mut length = fields::Uint24::empty();
    let mut x = record[HANDSHAKE_LENGTH_OFFSET..HANDSHAKE_LENGTH_OFFSET + size_of::<Length>()].to_vec();
    let _ = length.unpack(&mut x)?;
    Ok(length)
}

pub fn message_seq_from_record(record: Vec<u8>) -> Result<MessageSeq, errors::DTLSError> {
    if content_type_from_record(record.clone())? == record::ContentType::Handshake {
        Ok(fields::Uint16(BigEndian::read_u16(
            &record[MESSAGE_SEQ_OFFSET..MESSAGE_SEQ_OFFSET + size_of::<MessageSeq>()],
        )))
    } else {
        Ok(fields::Uint16(0))
    }
}

#[allow(dead_code)]
pub fn fragment_offset_from_record(record: Vec<u8>) -> Result<FragmentOffset, errors::DTLSError> {
    let mut fragment_offset = fields::Uint24::empty();
    let mut x = record[FRAGMENT_OFFSET_OFFSET..FRAGMENT_OFFSET_OFFSET + 6].to_vec();
    let _ = fragment_offset.unpack(&mut x)?;
    Ok(fragment_offset)
}

#[allow(dead_code)]
pub fn fragment_length_from_record(record: Vec<u8>) -> Result<FragmentLength, errors::DTLSError> {
    let mut fragment_length = fields::Uint24::empty();
    let mut x = record[FRAGMENT_LENGTH_OFFSET..FRAGMENT_LENGTH_OFFSET + 6].to_vec();
    let _ = fragment_length.unpack(&mut x)?;
    Ok(fragment_length)
}

#[derive(Clone, Debug)]
pub struct Handshake<Body>
where
    Body: ValidMessage + Pack,
{
    pub msg_type: HandshakeType,
    pub length: Length,
    pub message_seq: MessageSeq,
    pub fragment_offset: FragmentOffset,
    pub fragment_length: FragmentLength,
    pub body: Body,
}

impl<Body> Handshake<Body>
where
    Body: ValidMessage + Pack + Clone,
{
    pub fn new(message_seq: MessageSeq, body: Body) -> Result<Handshake<Body>, errors::DTLSError> {
        let mut length = [0; 3];
        let body_length = u32::try_from(body.len())?;
        BigEndian::write_u24(&mut length, body_length);
        let length: Length = fields::Uint24(length);
        let fragment_offset = fields::Uint24([0; 3]);
        let fragment_length = length;

        Ok(Self {
            msg_type: Body::into_handshake_type(),
            length,
            message_seq,
            fragment_offset,
            fragment_length,
            body,
        })
    }

    // New and unpacked handshakes are always defragmented, and therefore have Length = FragmentLength and FragmentOffset = 0
    #[allow(dead_code)]
    pub fn fix_reassembled_lengths(&self) -> Result<Self, errors::DTLSError> {
        let mut length = [0; 3];
        let body_length = u32::try_from(self.body.len())?;
        BigEndian::write_u24(&mut length, body_length);

        Ok(Self {
            msg_type: self.msg_type,
            length: fields::Uint24(length),
            message_seq: self.message_seq,
            fragment_offset: fields::Uint24([0; 3]),
            fragment_length: fields::Uint24(length),
            body: self.body.clone(),
        })
    }
}

impl<Body: ValidMessage + Pack> Pack for Handshake<Body>
where
    Body: ValidMessage + Pack,
{
    fn empty() -> Self {
        Self {
            msg_type: HandshakeType::empty(),
            length: Length::empty(),
            message_seq: MessageSeq::empty(),
            fragment_offset: FragmentOffset::empty(),
            fragment_length: FragmentLength::empty(),
            body: Body::empty(),
        }
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.msg_type.pack());
        v.extend_from_slice(&self.length.pack());
        v.extend_from_slice(&self.message_seq.pack());
        v.extend_from_slice(&self.fragment_offset.pack());
        v.extend_from_slice(&self.fragment_length.pack());
        v.extend_from_slice(&self.body.pack());
        v
    }

    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        let mut v = self.msg_type.unpack(v)?;
        let mut v = self.length.unpack(&mut v)?;
        let mut v = self.message_seq.unpack(&mut v)?;
        let mut v = self.fragment_offset.unpack(&mut v)?;
        let mut v = self.fragment_length.unpack(&mut v)?;
        let v = self.body.unpack(&mut v)?;
        Ok(v)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Random {
    gmt_unix_time: fields::Uint32,
    random_bytes: fields::Random,
}

impl Random {
    pub fn new(rand: &dyn SecureRandom) -> Result<Random, errors::DTLSError> {
        let mut random_bytes: [u8; 28] = [0; 28];
        let _ = rand.fill(&mut random_bytes); // TODO handle this error
        let random_bytes = fields::Random(random_bytes);

        let gmt_unix_time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
        let gmt_unix_time = u32::try_from(gmt_unix_time.as_secs())?;
        let gmt_unix_time = fields::Uint32(gmt_unix_time);
        Ok(Random { gmt_unix_time, random_bytes })
    }
}

impl Pack for Random {
    fn empty() -> Self {
        Self {
            gmt_unix_time: fields::Uint32::empty(),
            random_bytes: fields::Random::empty(),
        }
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.gmt_unix_time.pack());
        v.extend_from_slice(&self.random_bytes.pack());
        v
    }

    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        match v.len() {
            0..=31 => Err(errors::DTLSError::InvalidLengthError), // uint32 + Random = 4 + 28 = 32
            _ => {
                let rest: Vec<u8> = v.drain(32..).collect();
                let mut v = self.gmt_unix_time.unpack(v)?;
                let _ = self.random_bytes.unpack(&mut v)?;
                Ok(rest)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct SessionID {
    length: fields::Uint8,
    session_id: Vec<fields::Uint8>,
}

impl SessionID {
    pub fn new(v: Vec<u8>) -> Result<Self, errors::DTLSError> {
        match v.len() {
            0 => Ok(Self {
                length: fields::Uint8(0),
                session_id: Vec::new(),
            }),
            1 => Err(errors::DTLSError::InvalidLengthError),
            _ if (v[0] as usize != v.len() - 1) => Err(errors::DTLSError::InvalidLengthError),
            _ => {
                let mut length: Vec<fields::Uint8> = v.into_iter().map(fields::Uint8).collect();
                let v: Vec<fields::Uint8> = length.drain(1..).collect();
                Ok(Self {
                    length: length[0],
                    session_id: v,
                })
            }
        }
    }
}

impl Pack for SessionID {
    fn empty() -> Self {
        Self {
            length: fields::Uint8::empty(),
            session_id: Vec::new(),
        }
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.length.pack());
        let ext: Vec<u8> = self.session_id.clone().into_iter().flat_map(|i| i.pack()).collect();
        v.extend_from_slice(&ext);
        v
    }

    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        match v.len() {
            0..=1 => Err(errors::DTLSError::InvalidLengthError),
            _ if (v.len() - 1 < (v[0] as usize)) => Err(errors::DTLSError::InvalidLengthError),
            _ => {
                let length = usize::try_from(v[0])?;
                let mut field: Vec<u8> = v.drain(1..).collect();
                let rest: Vec<u8> = field.drain(length..).collect();
                let field: Vec<fields::Uint8> = field.into_iter().map(fields::Uint8).collect();
                self.length = fields::Uint8(length as u8);
                self.session_id = field;
                Ok(rest)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Cookie {
    pub length: fields::Uint8,
    cookie: Vec<fields::Uint8>,
}

impl Cookie {
    #[allow(dead_code)]
    pub fn new(v: Vec<u8>) -> Result<Self, errors::DTLSError> {
        match v.len() {
            0 => Ok(Self {
                length: fields::Uint8(0),
                cookie: Vec::new(),
            }),
            1 => Err(errors::DTLSError::InvalidLengthError),
            _ if (v[0] as usize != v.len() - 1) => Err(errors::DTLSError::InvalidLengthError),
            _ => {
                let mut length: Vec<fields::Uint8> = v.into_iter().map(fields::Uint8).collect();
                let v: Vec<fields::Uint8> = length.drain(1..).collect();
                Ok(Self {
                    length: length[0],
                    cookie: v,
                })
            }
        }
    }
}

impl Pack for Cookie {
    fn empty() -> Self {
        Self {
            length: fields::Uint8::empty(),
            cookie: Vec::new(),
        }
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.length.pack());
        let ext: Vec<u8> = self.cookie.clone().into_iter().flat_map(|i| i.pack()).collect();
        v.extend_from_slice(&ext);
        v
    }

    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        match v.len() {
            0..=1 => Err(errors::DTLSError::InvalidLengthError),
            _ if (v.len() - 1 < (v[0] as usize)) => Err(errors::DTLSError::InvalidLengthError),
            _ => {
                let length = usize::try_from(v[0])?;
                let mut field: Vec<u8> = v.drain(1..).collect();
                let rest: Vec<u8> = field.drain(length..).collect();
                let field: Vec<fields::Uint8> = field.into_iter().map(fields::Uint8).collect();
                self.length = fields::Uint8(length as u8);
                self.cookie = field;
                Ok(rest)
            }
        }
    }
}

pub type CipherSuite = fields::Uint16;

#[derive(Clone, Debug)]
pub struct CipherSuites {
    length: CipherSuite,
    cipher_suites: Vec<CipherSuite>,
}

impl CipherSuites {
    pub fn new(cipher_suites: Vec<fields::Uint16>) -> Result<CipherSuites, TryFromIntError> {
        let length = u16::try_from(cipher_suites.len() * 2)?;
        let length = fields::Uint16(length);
        Ok(CipherSuites { length, cipher_suites })
    }
}

impl Pack for CipherSuites {
    fn empty() -> Self {
        Self {
            length: fields::Uint16::empty(),
            cipher_suites: Vec::new(),
        }
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.length.pack());
        let ext: Vec<u8> = self.cipher_suites.clone().into_iter().flat_map(|i| i.pack()).collect();
        v.extend_from_slice(&ext);
        v
    }

    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        match v.len() {
            0..=1 => Err(errors::DTLSError::InvalidLengthError), // need both because length is a u16
            _ if (v.len() - 2 < (v[0] as usize)) => Err(errors::DTLSError::InvalidLengthError),
            _ => {
                let mut field: Vec<u8> = v.drain(2..).collect();
                let length = u16::from_be_bytes([v[0], v[1]]);
                self.length = fields::Uint16(length);
                let length = usize::try_from(length)?;
                let rest: Vec<u8> = field.drain(length..).collect();
                let field: Vec<fields::Uint16> = field.chunks_exact(2).map(|i| fields::Uint16(u16::from_be_bytes([i[0], i[1]]))).collect();
                self.cipher_suites = field;
                Ok(rest)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Primitive)]
#[repr(u8)]
pub enum CompressionMethod {
    Null = 0,
}

#[derive(Clone, Debug)]
pub struct CompressionMethods {
    length: fields::Uint8,
    compression_methods: Vec<CompressionMethod>,
}

impl CompressionMethods {
    pub fn new(compression_methods: Vec<CompressionMethod>) -> Result<CompressionMethods, TryFromIntError> {
        let length = u8::try_from(compression_methods.len())?;
        let length = fields::Uint8(length);
        Ok(CompressionMethods { length, compression_methods })
    }
}

impl Pack for CompressionMethods {
    fn empty() -> Self {
        Self {
            length: fields::Uint8::empty(),
            compression_methods: Vec::new(),
        }
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.length.pack());
        let ext: Vec<u8> = self.compression_methods.clone().into_iter().flat_map(|i| vec![i as u8]).collect();
        v.extend_from_slice(&ext);
        v
    }

    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        match v.len() {
            0..=1 => Err(errors::DTLSError::InvalidLengthError),
            _ if (v.len() - 1 < (v[0] as usize)) => Err(errors::DTLSError::InvalidLengthError),
            _ => {
                let length = usize::try_from(v[0])?;
                let mut field: Vec<u8> = v.drain(1..).collect();
                let rest: Vec<u8> = field.drain(length..).collect();
                let field: Vec<CompressionMethod> = field
                    .into_iter()
                    .flat_map(|e| CompressionMethod::from_u8(e).ok_or_else(|| errors::DTLSError::InvalidCompressionMethodError))
                    .collect();
                self.length = fields::Uint8(length as u8);
                self.compression_methods = field;
                Ok(rest)
            }
        }
    }
}

//
// Handshake messages
//

#[derive(Clone, Debug)]
pub struct ClientHello {
    pub client_version: record::ProtocolVersion,
    pub random: Random,
    pub session_id: SessionID,
    pub cookie: Cookie,
    pub cipher_suites: CipherSuites,
    pub compression_methods: CompressionMethods,
    pub client_hello_extension_list: extensions::ClientHelloExtensionList,
}
impl Pack for ClientHello {
    fn empty() -> Self {
        Self {
            client_version: record::ProtocolVersion::empty(),
            random: Random::empty(),
            session_id: SessionID::empty(),
            cookie: Cookie::empty(),
            cipher_suites: CipherSuites::empty(),
            compression_methods: CompressionMethods::empty(),
            client_hello_extension_list: extensions::ClientHelloExtensionList::empty(),
        }
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.client_version.pack());
        v.extend_from_slice(&self.random.pack());
        v.extend_from_slice(&self.session_id.pack());
        v.extend_from_slice(&self.cookie.pack());
        v.extend_from_slice(&self.cipher_suites.pack());
        v.extend_from_slice(&self.compression_methods.pack());
        v.extend_from_slice(&self.client_hello_extension_list.pack());
        v
    }

    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        let mut v = self.client_version.unpack(v)?;
        let mut v = self.random.unpack(&mut v)?;
        let mut v = self.session_id.unpack(&mut v)?;
        let mut v = self.cookie.unpack(&mut v)?;
        let mut v = self.cipher_suites.unpack(&mut v)?;
        let mut v = self.compression_methods.unpack(&mut v)?;
        let v = self.client_hello_extension_list.unpack(&mut v)?;
        Ok(v)
    }
}

#[derive(Clone, Debug)]
pub struct HelloVerifyRequest {
    pub server_version: record::ProtocolVersion,
    pub cookie: Cookie,
}

impl Pack for HelloVerifyRequest {
    fn empty() -> Self {
        Self {
            server_version: record::ProtocolVersion::empty(),
            cookie: Cookie::empty(),
        }
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.server_version.pack());
        v.extend_from_slice(&self.cookie.pack());
        v
    }

    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        let mut v = self.server_version.unpack(v)?;
        let v = self.cookie.unpack(&mut v)?;
        Ok(v)
    }
}

#[derive(Clone, Debug)]
pub struct ServerHello {
    pub server_version: record::ProtocolVersion,
    pub random: Random,
    pub session_id: SessionID,
    pub cipher_suite: CipherSuite,
    pub compression_method: CompressionMethod,
}
impl Pack for ServerHello {
    fn empty() -> Self {
        Self {
            server_version: record::ProtocolVersion::empty(),
            random: Random::empty(),
            session_id: SessionID::empty(),
            cipher_suite: fields::Uint16(0),
            compression_method: CompressionMethod::Null,
        }
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.server_version.pack());
        v.extend_from_slice(&self.random.pack());
        v.extend_from_slice(&self.session_id.pack());
        v.extend_from_slice(&self.cipher_suite.pack());
        v.extend_from_slice(&fields::Uint8(self.compression_method as u8).pack());
        v
    }

    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        let mut v = self.server_version.unpack(v)?;
        let mut v = self.random.unpack(&mut v)?;
        let mut v = self.session_id.unpack(&mut v)?;
        let mut v = self.cipher_suite.unpack(&mut v)?;

        let rest: Vec<u8> = v.drain(1..).collect(); // TODO just create a compression_method unpack
        let compression_method = CompressionMethod::from_u8(v[0]).ok_or_else(|| errors::DTLSError::InvalidCompressionMethodError)?;
        self.compression_method = compression_method;
        Ok(rest)
    }
}

#[derive(Clone, Debug)]
pub struct ServerHelloExtended {
    pub server_hello: ServerHello,
    pub extensions_length: fields::Uint16,
    pub extensions: Vec<u8>,
}
impl ValidMessage for ServerHelloExtended {
    fn into_handshake_type() -> HandshakeType {
        HandshakeType::ServerHello
    }
}
impl Pack for ServerHelloExtended {
    fn empty() -> Self {
        Self {
            server_hello: ServerHello::empty(),
            extensions_length: fields::Uint16(0),
            extensions: Vec::new(),
        }
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.server_hello.pack());
        v.extend_from_slice(&self.extensions_length.pack());
        v.extend_from_slice(&self.extensions[..]);
        v
    }

    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        let mut v = self.server_hello.unpack(v)?;
        let mut v = self.extensions_length.unpack(&mut v)?;
        let rest: Vec<u8> = v.drain(self.extensions_length.0 as usize..).collect();
        self.extensions = v;
        Ok(rest)
    }
}

#[derive(Clone, Debug)]
pub struct Certificate {
    pub length: fields::Uint24,
    pub certificate: Vec<u8>,
}

impl Certificate {
    #[allow(dead_code)]
    pub fn new(v: Vec<u8>) -> Result<Self, errors::DTLSError> {
        match v.len() {
            0 => Ok(Self {
                length: fields::Uint24([0; 3]),
                certificate: Vec::new(),
            }),
            _ => {
                // TODO implement the rest
                Ok(Self {
                    length: fields::Uint24([0; 3]),
                    certificate: Vec::new(),
                })
            }
        }
    }
}

impl Pack for Certificate {
    fn empty() -> Self {
        Self {
            length: fields::Uint24::empty(),
            certificate: Vec::new(),
        }
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.length.pack());
        v.extend_from_slice(&self.certificate);
        v
    }

    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        match v.len() {
            0..=3 => Err(errors::DTLSError::InvalidLengthError),
            _ => {
                let mut field: Vec<u8> = v.drain(3..).collect();
                self.length = fields::uint24_from_be_bytes([v[0], v[1], v[2]]);
                let length = usize::try_from(BigEndian::read_u24(&self.length.0))?;
                let rest: Vec<u8> = field.drain(length..).collect();
                self.certificate = field;
                Ok(rest)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Certificates {
    pub length: fields::Uint24,
    pub certificates: Vec<Certificate>,
}

impl Certificates {
    #[allow(dead_code)]
    pub fn new(certificates: Vec<Certificate>) -> Result<Certificates, TryFromIntError> {
        let mut length = [0; 3];
        BigEndian::write_u24(&mut length, certificates.len() as u32);
        let length = fields::Uint24(length);
        Ok(Self { length, certificates })
    }
}

impl Pack for Certificates {
    fn empty() -> Self {
        Self {
            length: fields::Uint24::empty(),
            certificates: Vec::new(),
        }
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.length.pack());
        let ext: Vec<u8> = self.certificates.clone().into_iter().flat_map(|i| i.pack()).collect();
        v.extend_from_slice(&ext);
        v
    }

    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        match v.len() {
            0..=3 => Err(errors::DTLSError::InvalidLengthError), // need both because length is a u24
            _ => {
                let mut field: Vec<u8> = v.drain(3..).collect();
                self.length = fields::uint24_from_be_bytes([v[0], v[1], v[2]]);

                let length = usize::try_from(BigEndian::read_u24(&self.length.0))?;
                let rest: Vec<u8> = field.drain(length..).collect();
                for _ in 0..length {
                    let mut certificate = Certificate::empty();
                    let _field = certificate.unpack(&mut field)?;
                    self.certificates.push(certificate);
                }
                Ok(rest)
            }
        }
    }
}

// EC Diffie-Hellman Server Params

#[derive(Debug, Copy, Clone, PartialEq, Primitive)]
#[repr(u8)]
pub enum ECCurveType {
    ExplicitPrime = 1,
    ExplicitChar2 = 2,
    NamedCurve = 3,
    //reserved(248..255)
}

#[derive(Debug, Copy, Clone, PartialEq, Primitive)]
#[repr(u16)]
pub enum NamedCurve {
    X25519 = 0x001d,
}

#[derive(Clone, Debug)]
pub struct ServerKeyExchange {
    ec_curve_type: ECCurveType,
    named_curve: NamedCurve,
    pubkey_length: fields::Uint8,
    pub pubkey: Vec<u8>,
    signature_length: fields::Uint16,
    signature: Vec<u8>,
}
impl Pack for ServerKeyExchange {
    fn empty() -> Self {
        Self {
            ec_curve_type: ECCurveType::NamedCurve,
            named_curve: NamedCurve::X25519,
            pubkey_length: fields::Uint8::empty(),
            pubkey: Vec::new(),
            signature_length: fields::Uint16::empty(),
            signature: Vec::new(),
        }
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&fields::Uint8(self.ec_curve_type as u8).pack());
        v.extend_from_slice(&fields::Uint16(self.named_curve as u16).pack());
        v.extend_from_slice(&self.pubkey_length.pack());
        v.extend_from_slice(&self.pubkey[..]);
        v.extend_from_slice(&self.signature_length.pack());
        v.extend_from_slice(&self.signature[..]);
        v
    }

    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        match v.len() {
            0..=12 => Err(errors::DTLSError::InvalidLengthError),
            _ => {
                let rest: Vec<u8> = v.drain(size_of::<u8>()..).collect();
                self.ec_curve_type = ECCurveType::from_u8(v[0]).ok_or_else(|| errors::DTLSError::InvalidHandshakeTypeError)?; // TODO better error
                let mut v = rest;

                let rest: Vec<u8> = v.drain(size_of::<u16>()..).collect();
                let named_curve = u16::from_be_bytes([v[0], v[1]]);
                self.named_curve = NamedCurve::from_u16(named_curve).ok_or_else(|| errors::DTLSError::InvalidHandshakeTypeError)?; // TODO better error
                let mut v = rest;

                let mut field: Vec<u8> = v.drain(size_of::<u8>()..).collect();

                self.pubkey_length = fields::Uint8(v[0]);
                let length = usize::try_from(v[0])?;
                let rest: Vec<u8> = field.drain(length..).collect();
                self.pubkey = field.to_vec();
                let mut v = rest;

                let mut field: Vec<u8> = v.drain(size_of::<u16>()..).collect();
                let length = u16::from_be_bytes([v[0], v[1]]);
                self.signature_length = fields::Uint16(length);

                let length = usize::try_from(length)?;
                let rest: Vec<u8> = field.drain(length..).collect();
                self.signature = field.to_vec();

                Ok(rest)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct ServerKeyExchangeExtended {
    ec_curve_type: ECCurveType,
    named_curve: NamedCurve,
    pubkey_length: fields::Uint8,
    pub pubkey: Vec<u8>,
    signature_algorithm_hash: fields::Uint8,
    signature_algorithm_signature: fields::Uint8,
    signature_length: fields::Uint16,
    signature: Vec<u8>,
}

impl ValidMessage for ServerKeyExchangeExtended {
    fn into_handshake_type() -> HandshakeType {
        HandshakeType::ServerKeyExchange
    }
}

impl Pack for ServerKeyExchangeExtended {
    fn empty() -> Self {
        Self {
            ec_curve_type: ECCurveType::NamedCurve,
            named_curve: NamedCurve::X25519,
            pubkey_length: fields::Uint8::empty(),
            pubkey: Vec::new(),
            signature_algorithm_hash: fields::Uint8::empty(),
            signature_algorithm_signature: fields::Uint8::empty(),
            signature_length: fields::Uint16::empty(),
            signature: Vec::new(),
        }
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&fields::Uint8(self.ec_curve_type as u8).pack());
        v.extend_from_slice(&fields::Uint16(self.named_curve as u16).pack());
        v.extend_from_slice(&self.pubkey_length.pack());
        v.extend_from_slice(&self.pubkey[..]);
        v.extend_from_slice(&self.signature_algorithm_hash.pack());
        v.extend_from_slice(&self.signature_algorithm_signature.pack());
        v.extend_from_slice(&self.signature_length.pack());
        v.extend_from_slice(&self.signature[..]);
        v
    }

    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        match v.len() {
            0..=12 => Err(errors::DTLSError::InvalidLengthError),
            _ => {
                let rest: Vec<u8> = v.drain(size_of::<u8>()..).collect();
                self.ec_curve_type = ECCurveType::from_u8(v[0]).ok_or_else(|| errors::DTLSError::InvalidHandshakeTypeError)?; // TODO better error
                let mut v = rest;

                let rest: Vec<u8> = v.drain(size_of::<u16>()..).collect();
                let named_curve = u16::from_be_bytes([v[0], v[1]]);
                self.named_curve = NamedCurve::from_u16(named_curve).ok_or_else(|| errors::DTLSError::InvalidHandshakeTypeError)?; // TODO better error
                let mut v = rest;

                let mut field: Vec<u8> = v.drain(size_of::<u8>()..).collect();

                self.pubkey_length = fields::Uint8(v[0]);
                let length = usize::try_from(v[0])?;
                let rest: Vec<u8> = field.drain(length..).collect();
                self.pubkey = field.to_vec();
                let mut v = rest;

                self.signature_algorithm_hash = fields::Uint8(v[0]);
                self.signature_algorithm_signature = fields::Uint8(v[1]);
                v = v[size_of::<u16>()..].to_vec();

                let mut field: Vec<u8> = v.drain(size_of::<u16>()..).collect();
                let length = u16::from_be_bytes([v[0], v[1]]);
                self.signature_length = fields::Uint16(length);

                let length = usize::try_from(length)?;
                let rest: Vec<u8> = field.drain(length..).collect();
                self.signature = field.to_vec();

                Ok(rest)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct ServerHelloDone;
impl Pack for ServerHelloDone {
    fn empty() -> Self {
        ServerHelloDone {}
    }
    fn pack(&self) -> Vec<u8> {
        Vec::new()
    }
    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        Ok(v.to_vec())
    }
}

// TODO make ClientKeyExchange generic, this is a specific case. Also, this is case explicit from RFC. How is case chosen?
#[derive(Clone, Debug)]
pub struct ClientDiffieHellmanPublic {
    pub pubkey_length: fields::Uint8,
    pub pubkey: Vec<fields::Uint8>,
}

impl ClientDiffieHellmanPublic {
    pub fn new(v: Vec<u8>) -> Result<Self, errors::DTLSError> {
        match v.len() {
            0 => Ok(Self {
                pubkey_length: fields::Uint8(0),
                pubkey: Vec::new(),
            }),
            1 => Err(errors::DTLSError::InvalidLengthError),
            _ => {
                let pubkey_length = fields::Uint8(u8::try_from(v.len())?);
                let pubkey: Vec<fields::Uint8> = v.into_iter().map(fields::Uint8).collect();
                Ok(Self { pubkey_length, pubkey })
            }
        }
    }
}

impl Pack for ClientDiffieHellmanPublic {
    fn empty() -> Self {
        Self {
            pubkey_length: fields::Uint8::empty(),
            pubkey: Vec::new(),
        }
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.pubkey_length.pack());
        let ext: Vec<u8> = self.pubkey.clone().into_iter().flat_map(|i| i.pack()).collect();
        v.extend_from_slice(&ext);
        v
    }

    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        match v.len() {
            0..=1 => Err(errors::DTLSError::InvalidLengthError),
            _ if (v.len() - 1 < (v[0] as usize)) => Err(errors::DTLSError::InvalidLengthError),
            _ => {
                let length = usize::try_from(v[0])?;
                let mut field: Vec<u8> = v.drain(1..).collect();
                let rest: Vec<u8> = field.drain(length..).collect();
                let field: Vec<fields::Uint8> = field.into_iter().map(fields::Uint8).collect();
                self.pubkey_length = fields::Uint8(length as u8);
                self.pubkey = field;
                Ok(rest)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct ClientKeyExchange {
    pub client_diffie_hellman_public: ClientDiffieHellmanPublic,
}

impl ClientKeyExchange {
    pub fn new(pub_key: Vec<u8>) -> Result<Self, errors::DTLSError> {
        Ok(Self {
            client_diffie_hellman_public: ClientDiffieHellmanPublic::new(pub_key)?,
        })
    }
}

impl Pack for ClientKeyExchange {
    fn empty() -> Self {
        Self {
            client_diffie_hellman_public: ClientDiffieHellmanPublic::empty(),
        }
    }

    fn pack(&self) -> Vec<u8> {
        self.client_diffie_hellman_public.pack()
    }

    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        self.client_diffie_hellman_public.unpack(v)
    }
}

pub const CLIENT_FINISHED_LABEL: &[u8; 15] = b"client finished";
#[allow(dead_code)]
pub const SERVER_FINISHED_LABEL: &[u8; 15] = b"server finished";

#[derive(Clone, Debug)]
pub struct Finished {
    verify_data: Vec<u8>,
}

impl Finished {
    pub fn new(verify_data: Vec<u8>) -> Self {
        Self { verify_data }
    }
}

impl Pack for Finished {
    fn empty() -> Self {
        Self { verify_data: Vec::new() }
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        let ext: Vec<u8> = self.verify_data.clone();
        v.extend_from_slice(&ext);
        v
    }

    fn unpack(&mut self, _v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        Ok(Vec::new()) // TODO
    }
}

#[cfg(test)]
mod tests {
    use crate::cipher;
    use crate::handshake;
    use crate::pack::Pack;
    use crate::pack_unpack_inverse_test;
    use crate::record;

    use hex;
    use ring::rand;

    // TODO HandshakeType
    /*
    ClientHello
    HelloVerifyRequest
    ServerHello
    Certificate
    Certificates
    ServerKeyExchange
    ServerKeyExchange
    ServerHelloDone;
    ClientDiffieHellmanPublic
    ClientKeyExchange
    Finished */

    pack_unpack_inverse_test!(
        random_pack_unpack_inverse_test,
        handshake::Random::new(&rand::SystemRandom::new()).expect("building Random failed")
    );
    pack_unpack_inverse_test!(
        session_id_pack_unpack_inverse_test,
        handshake::SessionID::new(vec![3, 1, 2, 3]).expect("building SessionId failed")
    );
    pack_unpack_inverse_test!(
        cookie_pack_unpack_inverse_test,
        handshake::Cookie::new(vec![4, 4, 3, 2, 1]).expect("building Cookie failed")
    );
    pack_unpack_inverse_test!(
        cipher_suites_unpack_inverse_test,
        handshake::CipherSuites::new(vec![
            cipher::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            cipher::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            cipher::TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            cipher::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            cipher::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            cipher::TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            cipher::TLS_RSA_WITH_AES_256_CBC_SHA,
            cipher::TLS_RSA_WITH_AES_128_CBC_SHA,
            cipher::TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
        ])
        .expect("building CipherSuites failed")
    );
    pack_unpack_inverse_test!(
        compression_methods_pack_unpack_inverse_test,
        handshake::CompressionMethods::new(vec![handshake::CompressionMethod::Null]).expect("building CompressionMethods failed")
    );

    #[test]
    fn offsets() {
        let mut client_hello_bytes = hex::decode(
            "16feff0000000000000000009c010000900000000000000090fefdc821f155aeafa616f4f942faede721055f1a21467ae21934938730f16f479c7e00000004c01400ff01000062000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000016000000170000000d0030002e040305030603080708080809080a080b080408050806040105010601030302030301020103020202040205020602"
        ).expect("ClientHello decode failed");

        let mut client_hello = record::DTLSPlaintext::<handshake::ClientHello>::empty();
        let _ = client_hello.unpack(&mut client_hello_bytes);
        assert_eq!(
            handshake::handshake_type_from_record(client_hello.pack()).expect("invalid handshake type"),
            handshake::HandshakeType::ClientHello
        );
        //TODO the rest: PROTOCOL_VERSION_OFFSET, EPOCH_OFFSET, etc
    }
}
