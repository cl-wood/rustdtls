use crate::change_cipher_spec;
use crate::crypto;
use crate::errors;
use crate::fields;
use crate::handshake;
use crate::pack::Pack;

use byteorder::{BigEndian, ByteOrder};
use num_traits::FromPrimitive;
use std::convert::TryFrom;
use std::mem::size_of;
use std::num::TryFromIntError;

#[derive(Clone, Copy, Debug)]
pub struct ProtocolVersion {
    major: fields::Uint8,
    minor: fields::Uint8,
}
impl Pack for ProtocolVersion {
    fn empty() -> Self {
        Self {
            major: fields::Uint8(0),
            minor: fields::Uint8(0),
        }
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(self.major.0);
        v.push(self.minor.0);
        v
    }

    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        match v.len() {
            0..=1 => Err(errors::DTLSError::InvalidLengthError),
            _ => {
                let rest: Vec<u8> = v.drain(2..).collect();
                self.major = fields::Uint8(v[0]);
                self.minor = fields::Uint8(v[1]);
                Ok(rest)
            }
        }
    }
}

#[allow(dead_code)]
pub const VERSION: ProtocolVersion = ProtocolVersion {
    major: fields::Uint8(254),
    minor: fields::Uint8(255),
};

pub const DTLS_1_2: ProtocolVersion = ProtocolVersion {
    major: fields::Uint8(254),
    minor: fields::Uint8(253),
};

#[derive(Debug, Copy, Clone, Primitive, PartialEq)]
#[repr(u8)]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}
impl Pack for ContentType {
    fn empty() -> Self {
        ContentType::Handshake
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
                let rest: Vec<u8> = v.drain(1..).collect(); // TODO probably faster ways with pop on mutable vecs
                *self = Self::from_u8(v[0]).ok_or_else(|| errors::DTLSError::InvalidContentTypeError)?;
                Ok(rest)
            }
        }
    }
}

pub type Epoch = fields::Uint16;
pub type SequenceNumber = fields::Uint48;
pub type Length = fields::Uint16;

pub fn epoch_from_record(record: Vec<u8>) -> Epoch {
    let epoch_offset = size_of::<ContentType>() + size_of::<ProtocolVersion>();
    fields::Uint16(BigEndian::read_u16(&record[epoch_offset..epoch_offset + 2]))
}

pub fn sequence_number_from_record(record: Vec<u8>) -> Result<SequenceNumber, errors::DTLSError> {
    let epoch_offset = size_of::<ContentType>() + size_of::<ProtocolVersion>() + size_of::<Epoch>();
    let mut sequence_number = fields::Uint48::empty();
    let mut x = record[epoch_offset..epoch_offset + 6].to_vec();
    let _ = sequence_number.unpack(&mut x)?;
    Ok(sequence_number)
}

// TODO merge this with DTLSPlaintext<Body>, which should instead have a "ValidRecord", similar to ValidMessage, but for alert, changecipherspec, handshake, etc
#[derive(Clone, Debug)]
pub struct DTLSPlaintext_change_cipher_spec {
    pub r#type: ContentType,
    pub version: ProtocolVersion,
    pub epoch: Epoch,
    pub sequence_number: SequenceNumber,
    pub length: Length,
    pub change_cipher_spec: change_cipher_spec::ChangeCipherSpec,
}
impl Pack for DTLSPlaintext_change_cipher_spec {
    fn empty() -> Self {
        Self {
            r#type: ContentType::empty(),
            version: ProtocolVersion::empty(),
            epoch: Epoch::empty(),
            sequence_number: SequenceNumber::empty(),
            length: Length::empty(),
            change_cipher_spec: change_cipher_spec::ChangeCipherSpec::empty(),
        }
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.r#type.pack());
        v.extend_from_slice(&self.version.pack());
        v.extend_from_slice(&self.epoch.pack());
        v.extend_from_slice(&self.sequence_number.pack());
        v.extend_from_slice(&self.length.pack());
        v.extend_from_slice(&self.change_cipher_spec.pack());
        v
    }

    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        let mut v = self.r#type.unpack(v)?;
        let mut v = self.version.unpack(&mut v)?;
        let mut v = self.epoch.unpack(&mut v)?;
        let mut v = self.sequence_number.unpack(&mut v)?;
        let mut v = self.length.unpack(&mut v)?;
        let v = self.change_cipher_spec.unpack(&mut v)?;
        Ok(v)
    }
}

// TODO remove after we've got DTLSCiphertext Finished working
#[derive(Clone, Debug)]
pub struct DTLSPlaintextEncryptedFinished {
    pub r#type: ContentType,
    pub version: ProtocolVersion,
    pub epoch: Epoch,
    pub sequence_number: SequenceNumber,
    pub length: Length,
    pub encrypted: Vec<u8>,
}
impl DTLSPlaintextEncryptedFinished {
    #[allow(dead_code)]
    pub fn new(
        r#type: ContentType,
        version: ProtocolVersion,
        epoch: Epoch,
        sequence_number: SequenceNumber,
        encrypted: Vec<u8>,
    ) -> Result<Self, TryFromIntError> {
        let length: Length = fields::Uint16(u16::try_from(encrypted.len())?);

        Ok(Self {
            r#type,
            version,
            epoch,
            sequence_number,
            length,
            encrypted,
        })
    }
}
impl Pack for DTLSPlaintextEncryptedFinished {
    fn empty() -> Self {
        Self {
            r#type: ContentType::empty(),
            version: ProtocolVersion::empty(),
            epoch: Epoch::empty(),
            sequence_number: SequenceNumber::empty(),
            length: Length::empty(),
            encrypted: Vec::new(),
        }
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.r#type.pack());
        v.extend_from_slice(&self.version.pack());
        v.extend_from_slice(&self.epoch.pack());
        v.extend_from_slice(&self.sequence_number.pack());
        v.extend_from_slice(&self.length.pack());
        v.extend_from_slice(&self.encrypted);
        v
    }

    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        let mut v = self.r#type.unpack(v)?;
        let mut v = self.version.unpack(&mut v)?;
        let mut v = self.epoch.unpack(&mut v)?;
        let mut v = self.sequence_number.unpack(&mut v)?;
        let v = self.length.unpack(&mut v)?;
        //let v = self.encrypted.unpack(&mut v)?; TODO handle encrypted unpacking
        Ok(v)
    }
}

// TODO, create newtypes out of these primitives(check), add refinements with new() if there are any conditions beyond "is a u16"
#[derive(Clone, Debug)]
pub struct DTLSPlaintext<Body>
where
    Body: handshake::ValidMessage + Pack,
{
    pub r#type: ContentType,
    pub version: ProtocolVersion,
    pub epoch: Epoch,
    pub sequence_number: SequenceNumber,
    pub length: Length,
    pub fragment: handshake::Handshake<Body>,
}

impl<Body> DTLSPlaintext<Body>
where
    Body: handshake::ValidMessage + Pack,
{
    pub fn new(
        r#type: ContentType,
        version: ProtocolVersion,
        epoch: Epoch,
        sequence_number: SequenceNumber,
        fragment: handshake::Handshake<Body>,
    ) -> Result<DTLSPlaintext<Body>, TryFromIntError> {
        let length: Length = fields::Uint16(u16::try_from(fragment.len())?);

        Ok(DTLSPlaintext {
            r#type,
            version,
            epoch,
            sequence_number,
            length,
            fragment,
        })
    }
}

impl<Body> Pack for DTLSPlaintext<Body>
where
    Body: handshake::ValidMessage + Pack,
{
    fn empty() -> Self {
        Self {
            r#type: ContentType::empty(),
            version: ProtocolVersion::empty(),
            epoch: Epoch::empty(),
            sequence_number: SequenceNumber::empty(),
            length: Length::empty(),
            fragment: handshake::Handshake::empty(),
        }
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.r#type.pack());
        v.extend_from_slice(&self.version.pack());
        v.extend_from_slice(&self.epoch.pack());
        v.extend_from_slice(&self.sequence_number.pack());
        v.extend_from_slice(&self.length.pack());
        v.extend_from_slice(&self.fragment.pack());
        v
    }

    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        let mut v = self.r#type.unpack(v)?;
        let mut v = self.version.unpack(&mut v)?;
        let mut v = self.epoch.unpack(&mut v)?;
        let mut v = self.sequence_number.unpack(&mut v)?;
        let mut v = self.length.unpack(&mut v)?;
        let v = self.fragment.unpack(&mut v)?;
        Ok(v)
    }
}

#[allow(dead_code)]
struct DTLSCompressed {
    r#type: ContentType,
    version: ProtocolVersion,
    epoch: Epoch,
    sequence_number: SequenceNumber,
    length: Length,
    fragment: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct DTLSCiphertext {
    pub r#type: ContentType,
    pub version: ProtocolVersion,
    pub epoch: Epoch,
    pub sequence_number: SequenceNumber,
    pub length: Length,
    pub fragment: GenericBlockCipher,
}

impl DTLSCiphertext {
    // TODO can use this to create from DTLSCompressed, SecurityParameters, KeyBlock, and have DTLSCompressed new take a Plaintext
    // Basicically move from_dtls_plaintext() to new()
    pub fn new(
        r#type: ContentType,
        version: ProtocolVersion,
        epoch: Epoch,
        sequence_number: SequenceNumber,
        fragment: GenericBlockCipher,
    ) -> Result<Self, TryFromIntError> {
        let length: Length = fields::Uint16(u16::try_from(fragment.len())?);

        Ok(Self {
            r#type,
            version,
            epoch,
            sequence_number,
            length,
            fragment,
        })
    }

    // TODO should actually always go Plaintext -> Compressed -> Ciphertext, even with Null compression
    pub fn from_dtls_plaintext(
        p: DTLSPlaintext<handshake::Finished>,
        security_parameters: &crypto::SecurityParameters,
        _key_block: &crypto::KeyBlock,
    ) -> Result<Self, errors::DTLSError> {
        // TODO if not supporting encrypt-then-mac extension, probably pass an extensions struct
        let block_ciphered = BlockCiphered::new(p.fragment.pack(), None, security_parameters.cipher_parameters.block_length.0 as usize);
        let generic_block_cipher = GenericBlockCipher::new(block_ciphered);

        Ok(Self {
            r#type: p.r#type,
            version: p.version,
            epoch: p.epoch,
            sequence_number: p.sequence_number,
            length: fields::Uint16(generic_block_cipher.len() as u16),
            fragment: generic_block_cipher,
        })
    }

    pub fn encrypt(
        &self,
        iv: &[u8],
        security_parameters: &crypto::SecurityParameters,
        key_block: &crypto::KeyBlock,
    ) -> Result<Vec<u8>, errors::DTLSError> {
        // TODO probably pass an extensions struct to decide if encrypt-then-mac, etc
        let ciphered_block = crypto::encrypt_then_mac(
            iv,
            self.fragment.block_ciphered.pack(),
            security_parameters,
            key_block,
            self.epoch,
            self.sequence_number,
            self.r#type,
            self.version,
        )?;

        let mut v = Vec::new();
        v.extend_from_slice(&self.r#type.pack());
        v.extend_from_slice(&self.version.pack());
        v.extend_from_slice(&self.epoch.pack());
        v.extend_from_slice(&self.sequence_number.pack());
        v.extend_from_slice(&fields::Uint16(ciphered_block.len() as u16).pack());
        let encrypted_block: Vec<fields::Uint8> = ciphered_block.into_iter().map(|i| fields::Uint8(i)).collect();
        v.extend_from_slice(&encrypted_block.pack());
        Ok(v)
    }

    pub fn decrypt(
        ciphertext: &[u8],
        security_parameters: &crypto::SecurityParameters,
        key_block: &crypto::KeyBlock,
    ) -> Result<Vec<u8>, errors::DTLSError> {
        let iv_length = security_parameters.cipher_parameters.record_iv_length.0 as usize;
        let mac_length = security_parameters.cipher_parameters.mac_length.0 as usize;
        let iv = &ciphertext[..iv_length];
        let c = &ciphertext[iv_length..ciphertext.len() - mac_length];
        let mac = &ciphertext[mac_length..];

        let plaintext = crypto::decrypt(iv, c, mac, security_parameters, key_block)?;

        // TODO

        Ok(plaintext)
    }
}

impl Pack for DTLSCiphertext {
    fn empty() -> Self {
        Self {
            r#type: ContentType::empty(),
            version: ProtocolVersion::empty(),
            epoch: Epoch::empty(),
            sequence_number: SequenceNumber::empty(),
            length: Length::empty(),
            fragment: GenericBlockCipher::empty(),
        }
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.r#type.pack());
        v.extend_from_slice(&self.version.pack());
        v.extend_from_slice(&self.epoch.pack());
        v.extend_from_slice(&self.sequence_number.pack());
        v.extend_from_slice(&self.length.pack());
        v.extend_from_slice(&self.fragment.pack());
        v
    }

    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        let mut v = self.r#type.unpack(v)?;
        let mut v = self.version.unpack(&mut v)?;
        let mut v = self.epoch.unpack(&mut v)?;
        let mut v = self.sequence_number.unpack(&mut v)?;
        let v = self.length.unpack(&mut v)?;
        Ok(v)
    }
}

#[derive(Clone, Debug)]
pub struct BlockCiphered {
    content: Vec<u8>,
    // Options, to support Encrypt-then-MAC
    mac: Option<Vec<u8>>,
    padding: Vec<fields::Uint8>,
    padding_length: fields::Uint8,
}

impl BlockCiphered {
    pub fn new(content: Vec<u8>, mac: Option<Vec<u8>>, block_length: usize) -> Self {
        let content_length = fields::Uint8(content.len() as u8);

        let mac_length = match mac.clone() {
            Some(mac) => Some(fields::Uint8(mac.len() as u8)),
            None => None,
        };

        let padding_length = match mac_length {
            Some(mac) => {
                let rem = (/*2 * size_of::<fields::Uint8>() + */content_length.0 as usize + mac.0 as usize) % block_length;
                block_length - (rem + 1)
            }
            None => {
                let rem = (/*size_of::<fields::Uint8>() +*/content_length.0 as usize) % block_length;
                block_length - (rem + 1)
            }
        };

        // TODO not sure how this handles blocks that need 0 padding
        let padding = vec![fields::Uint8(padding_length as u8); padding_length];

        Self {
            content,
            mac,
            padding,
            padding_length: fields::Uint8(padding_length as u8),
        }
    }
}

impl Pack for BlockCiphered {
    fn empty() -> Self {
        Self {
            content: Vec::new(),
            mac: None,
            padding: Vec::new(),
            padding_length: fields::Uint8(0),
        }
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        let ext: Vec<u8> = self.content.clone();
        v.extend_from_slice(&ext);

        /*
        match &self.mac_length {
            None => (),
            Some(mac_length) => v.extend_from_slice(&mac_length.pack()),
        }*/
        match &self.mac {
            None => (),
            Some(mac) => v.extend_from_slice(&mac),
        }

        //v.extend_from_slice(&self.padding_length.pack());
        let ext: Vec<u8> = self.padding.clone().into_iter().map(|i| i.0).collect();
        v.extend_from_slice(&ext);
        v.extend_from_slice(&self.padding_length.pack());
        v
    }

    fn unpack(&mut self, _v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        Ok(Vec::new()) // TODO
    }
}

#[derive(Clone, Debug)]
pub struct GenericBlockCipher {
    iv: Vec<u8>,
    block_ciphered: BlockCiphered,
}
impl GenericBlockCipher {
    pub fn new(block_ciphered: BlockCiphered) -> Self {
        Self {
            iv: Vec::new(),
            block_ciphered,
        }
    }
}
impl Pack for GenericBlockCipher {
    fn empty() -> Self {
        Self {
            iv: Vec::new(),
            block_ciphered: BlockCiphered::empty(),
        }
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        let ext: Vec<u8> = self.iv.clone();
        v.extend_from_slice(&ext);
        v.extend_from_slice(&self.block_ciphered.pack());
        v
    }

    fn unpack(&mut self, _v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        Ok(Vec::new()) // TODO in order to unpack iv, need to know it's length. Use new() to configure something like IV-len? Consume key_block data?
    }
}

/*
struct GenericStreamCipher {
    opaque content[TLSCompressed.length],
    opaque MAC[SecurityParameters.mac_length],
}

struct GenericAEADCipher {
    opaque nonce_explicit[SecurityParameters.record_iv_length];
    aead-ciphered struct {
        opaque content[TLSCompressed.length];
    };
}
*/

#[cfg(test)]
mod tests {
    use crate::pack::Pack;
    use crate::record;

    #[test]
    fn content_type_pack_unpack_are_inverse() {
        let mut content_type = record::ContentType::empty();
        let mut i = [20, 2].to_vec();
        let _ = content_type.unpack(&mut i);
        let j = content_type.pack();
        assert_eq!([20].to_vec(), j);
    }

    #[test]
    fn protocol_version_pack_unpack_are_inverse() {
        let mut client_version = record::ProtocolVersion::empty();
        let mut i = [1, 2].to_vec();
        let _ = client_version.unpack(&mut i);
        let j = client_version.pack();
        assert_eq!(i, j);
    }
}
