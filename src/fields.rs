use byteorder::{BigEndian, ByteOrder};
use std::ops::{Add, Rem, Sub};

pub type NetVec<T> = Vec<T>;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Uint8(pub u8);
impl Add for Uint8 {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self { 0: self.0 + other.0 }
    }
}
impl Rem for Uint8 {
    type Output = Self;

    fn rem(self, other: Self) -> Self {
        Self { 0: self.0 % other.0 }
    }
}
impl Sub for Uint8 {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Self { 0: self.0 - other.0 }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Uint16(pub u16);
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Uint32(pub u32);

// In network order (Big Endian)
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Uint24(pub [u8; 3]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Uint48(pub [u8; 6]);

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Random(pub [u8; 28]);

// TODO add += 1 for Uint24 and Uint16
pub fn increment_uint16(i: Uint16) -> Uint16 {
    Uint16(i.0 + 1)
}
pub fn increment_uint48(i: Uint48) -> Uint48 {
    let mut buf = [0; 6];
    BigEndian::write_u48(&mut buf, BigEndian::read_u48(&i.0) + 1);
    Uint48(buf)
}

#[allow(dead_code)]
pub fn uint24_to_u32(i: Uint24) -> u32 {
    BigEndian::read_u24(&i.0)
}

pub fn uint48_to_u64(i: Uint48) -> u64 {
    BigEndian::read_u48(&i.0)
}

pub fn uint24_from_be_bytes(bytes: [u8; 3]) -> Uint24 {
    Uint24(bytes)
}

pub fn uint48_from_be_bytes(bytes: [u8; 6]) -> Uint48 {
    Uint48(bytes)
}
