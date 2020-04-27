use crate::errors;
use crate::fields;
use crate::pack::Pack;

use num_traits::FromPrimitive;
use std::convert::TryFrom;
use std::mem::size_of;

#[derive(Debug, Copy, Clone, PartialEq, Primitive)]
#[repr(u16)]
enum ExtensionType {
    ServerName = 0,
    MaxFragmentLength = 1,
    ClientCertificateUrl = 2,
    TrustedCaKeys = 3,
    TruncatedHmac = 4,
    StatusRequest = 5,

    SupportedGroups = 10,
    EcPointFormats = 11,

    EncryptThenMac = 22,
}

#[derive(Debug, Clone)]
pub struct Extension {
    extension_type: ExtensionType,
    extension_data_length: fields::Uint16,
    extension_data: Vec<fields::Uint8>,
}

impl Pack for Extension {
    fn empty() -> Self {
        Self {
            extension_type: ExtensionType::ServerName,
            extension_data_length: fields::Uint16::empty(),
            extension_data: Vec::new(),
        }
    }
    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        let extension_type = fields::Uint16(self.extension_type as u16);
        v.extend_from_slice(&extension_type.pack());
        v.extend_from_slice(&self.extension_data_length.pack());
        v.extend_from_slice(&self.extension_data.pack());
        v
    }

    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        match v.len() {
            0..=1 => Err(errors::DTLSError::InvalidLengthError),
            _ if (v.len() - 1 < (v[0] as usize)) => Err(errors::DTLSError::InvalidLengthError),
            _ => {
                let mut field: Vec<u8> = v.drain(size_of::<ExtensionType>()..).collect();
                self.extension_type =
                    ExtensionType::from_u16(u16::from_be_bytes([v[0], v[1]])).ok_or_else(|| errors::DTLSError::InvalidCompressionMethodError)?;

                let mut field2: Vec<u8> = field.drain(size_of::<u16>()..).collect();
                let length = u16::from_be_bytes([field[0], field[1]]);
                self.extension_data_length = fields::Uint16(length);

                let length = usize::try_from(length)?;
                let rest: Vec<u8> = field2.drain(length..).collect();

                self.extension_data = field2.into_iter().map(|i| fields::Uint8(i)).collect();

                Ok(rest)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct ClientHelloExtensionList {
    length: fields::Uint16,
    extensions: Vec<Extension>,
}

impl ClientHelloExtensionList {
    pub fn new(extensions: Vec<Extension>) -> Self {
        let length = fields::Uint16(extensions.iter().map(|i| i.len()).sum::<usize>() as u16); // TODO all of these 'as' into try_intos/try_froms/etc
        Self { length, extensions }
    }
}

impl Pack for ClientHelloExtensionList {
    fn empty() -> Self {
        Self {
            length: fields::Uint16::empty(),
            extensions: Vec::new(),
        }
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.length.pack());
        let ext: Vec<u8> = self.extensions.clone().into_iter().flat_map(|i| i.pack()).collect();
        v.extend_from_slice(&ext[..]);
        v
    }

    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        match v.len() {
            0..=2 => Err(errors::DTLSError::InvalidLengthError),
            _ => {
                self.extensions = Vec::new();

                let mut field: Vec<u8> = v.drain(size_of::<u16>()..).collect();
                let length = u16::from_be_bytes([v[0], v[1]]);
                self.length = fields::Uint16(length);

                // just unpack all the extension bytes for now
                //let rest: Vec<u8> = field.drain(length as usize..).collect();

                // just do it twice for now
                let mut extension1 = Extension::empty();
                let mut rest = extension1.unpack(&mut field)?;
                self.extensions.push(extension1);

                let mut extension2 = Extension::empty();
                let rest = extension2.unpack(&mut rest)?;
                self.extensions.push(extension2);

                Ok(rest)
            }
        }
    }
}

pub const EC_POINT_FORMATS_LENGTH: fields::Uint8 = fields::Uint8(3);
pub const UNCOMPRESSED: fields::Uint8 = fields::Uint8(0);
pub const ANSIX962_COMPRESSED_PRIME: fields::Uint8 = fields::Uint8(1);
pub const ANSIX962_COMPRESSED_CHAR2: fields::Uint8 = fields::Uint8(2);

pub fn ec_point_formats() -> Extension {
    Extension {
        extension_type: ExtensionType::EcPointFormats,
        extension_data_length: fields::Uint16(4),
        extension_data: vec![
            EC_POINT_FORMATS_LENGTH,
            UNCOMPRESSED,
            ANSIX962_COMPRESSED_PRIME,
            ANSIX962_COMPRESSED_CHAR2,
        ],
    }
}

pub fn supported_groups() -> Extension {
    let data = vec![0x00, 0x0a, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00, 0x19, 0x00, 0x18];
    let data: Vec<fields::Uint8> = data.into_iter().map(|i| fields::Uint8(i)).collect();
    Extension {
        extension_type: ExtensionType::SupportedGroups,
        extension_data_length: fields::Uint16(12),
        extension_data: data,
    }
}

pub fn encrypt_then_mac() -> Extension {
    Extension {
        extension_type: ExtensionType::EncryptThenMac,
        extension_data_length: fields::Uint16(0),
        extension_data: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use crate::extensions;
    use crate::pack::Pack;
    use crate::pack_unpack_inverse_test;

    pack_unpack_inverse_test!(supported_groups_pack_unpack_inverse_test, extensions::supported_groups());

    pack_unpack_inverse_test!(ec_point_formats_pack_unpack_inverse_test, extensions::ec_point_formats());

    pack_unpack_inverse_test!(
        client_hello_extension_list_pack_unpack_inverse_test,
        extensions::ClientHelloExtensionList::new(vec![extensions::ec_point_formats(), extensions::supported_groups()])
    );
}
