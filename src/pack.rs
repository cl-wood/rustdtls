use crate::errors;
use crate::fields;

use byteorder::{BigEndian, ByteOrder};

// TODO reimplement this using bytes::BufMut? Could use put to pack values, get to unpack.
// Get to the point where we test sending something large before we optimize
pub trait Pack {
    fn empty() -> Self;
    fn len(&self) -> usize {
        self.pack().len()
    }
    fn pack(&self) -> Vec<u8>;
    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError>;
}

impl<E> Pack for fields::NetVec<E>
where
    E: Pack + Clone,
{
    fn empty() -> Self {
        fields::NetVec::new()
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        for e in self {
            v.extend_from_slice(&*e.pack());
        }
        v
    }

    fn unpack(&mut self, _v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        Err(errors::DTLSError::InvalidLengthError)
    }
}

impl Pack for fields::Uint8 {
    fn empty() -> Self {
        fields::Uint8(0)
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(self.0);
        v
    }
    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        match v.len() {
            0 => Err(errors::DTLSError::InvalidLengthError),
            _ => {
                let rest: Vec<u8> = v.drain(1..).collect();
                self.0 = v[0];
                Ok(rest)
            }
        }
    }
}

impl Pack for fields::Uint16 {
    fn empty() -> Self {
        fields::Uint16(0)
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        let mut bytes: [u8; 2] = [0; 2];
        BigEndian::write_u16(&mut bytes, self.0);
        v.extend_from_slice(&bytes);
        v
    }

    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        match v.len() {
            0..=1 => Err(errors::DTLSError::InvalidLengthError),
            _ => {
                let rest: Vec<u8> = v.drain(2..).collect();
                let some_u16: Vec<u16> = v.chunks_exact(2).map(|i| u16::from_be_bytes([i[0], i[1]])).collect();
                self.0 = some_u16[0];
                Ok(rest)
            }
        }
    }
}

impl Pack for fields::Uint24 {
    fn empty() -> Self {
        fields::Uint24([0; 3])
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.0);
        v
    }
    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        match v.len() {
            0..=2 => Err(errors::DTLSError::InvalidLengthError),
            _ => {
                let rest: Vec<u8> = v.drain(3..).collect();
                let some_u24: Vec<fields::Uint24> = v.chunks_exact(3).map(|i| fields::uint24_from_be_bytes([i[0], i[1], i[2]])).collect();
                self.0 = some_u24[0].0;
                Ok(rest)
            }
        }
    }
}

impl Pack for fields::Uint32 {
    fn empty() -> Self {
        fields::Uint32(0)
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        let mut bytes: [u8; 4] = [0; 4];
        BigEndian::write_u32(&mut bytes, self.0);
        v.extend_from_slice(&bytes);
        v
    }
    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        match v.len() {
            0..=3 => Err(errors::DTLSError::InvalidLengthError),
            _ => {
                let rest: Vec<u8> = v.drain(4..).collect();
                let some_u32: Vec<u32> = v.chunks_exact(4).map(|i| u32::from_be_bytes([i[0], i[1], i[2], i[3]])).collect();
                self.0 = some_u32[0];
                Ok(rest)
            }
        }
    }
}

impl Pack for fields::Uint48 {
    fn empty() -> Self {
        fields::Uint48([0; 6])
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.0);
        v
    }
    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        match v.len() {
            0..=5 => Err(errors::DTLSError::InvalidLengthError),
            _ => {
                let rest: Vec<u8> = v.drain(6..).collect();
                let some_u48: Vec<fields::Uint48> = v
                    .chunks_exact(6)
                    .map(|i| fields::uint48_from_be_bytes([i[0], i[1], i[2], i[3], i[4], i[5]]))
                    .collect();
                self.0 = some_u48[0].0;
                Ok(rest)
            }
        }
    }
}

impl Pack for fields::Random {
    fn empty() -> Self {
        fields::Random([0; 28])
    }

    fn pack(&self) -> Vec<u8> {
        self.0.to_vec()
    }
    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        match v.len() {
            1..=27 => Err(errors::DTLSError::InvalidLengthError), // TODO use size_of Random instead of 27
            _ => {
                let rest: Vec<u8> = v.drain(28..).collect();
                let mut random = [0; 28];
                let bytes = &v[..random.len()]; // panics if not enough data, but based on the match we should be fine
                random.copy_from_slice(bytes);
                self.0 = random;
                Ok(rest)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::fields;
    use crate::pack::Pack;
    use crate::pack_unpack_inverse_test;

    // TODO pack_unpack_are_inverse for the rest

    pack_unpack_inverse_test!(uint8_pack_unpack_inverse_test, fields::Uint8(14));

    pack_unpack_inverse_test!(uint16_pack_unpack_inverse_test, fields::Uint16(9));

    pack_unpack_inverse_test!(uint24_pack_unpack_inverse_test, fields::Uint24([250, 100, 4]));

    pack_unpack_inverse_test!(uint32_pack_unpack_inverse_test, fields::Uint32(7777));

    pack_unpack_inverse_test!(uint48_pack_unpack_inverse_test, fields::Uint48([1, 2, 3, 4, 5, 6]));

    pack_unpack_inverse_test!(random_pack_unpack_inverse_test, fields::Random::empty());
}
