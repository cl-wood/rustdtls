use crate::errors;
use crate::pack::Pack;

use num_traits::FromPrimitive;
use std::mem::size_of;

#[derive(Debug, Copy, Clone, PartialEq, Primitive)]
#[repr(u8)]
pub enum Type {
    ChangeCipherSpec = 1,
}

#[derive(Clone, Debug)]
pub struct ChangeCipherSpec {
    pub r#type: Type,
}

impl Pack for ChangeCipherSpec {
    fn empty() -> Self {
        Self {
            r#type: Type::ChangeCipherSpec,
        }
    }

    fn pack(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(self.r#type as u8);
        v
    }
    fn unpack(&mut self, v: &mut Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
        match v.len() {
            0 => Err(errors::DTLSError::InvalidLengthError),
            _ => {
                let rest: Vec<u8> = v.drain(size_of::<Type>()..).collect();
                self.r#type = Type::from_u8(v[0]).ok_or_else(|| errors::DTLSError::InvalidCompressionMethodError)?;
                Ok(rest)
            }
        }
    }
}
