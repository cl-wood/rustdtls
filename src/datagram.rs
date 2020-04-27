use crate::record;

use byteorder::{BigEndian, ByteOrder};
use std::mem::size_of;

pub fn datagram_to_records(buf: Vec<u8>) -> Vec<Vec<u8>> {
    let length_offset =
        size_of::<record::ContentType>() + size_of::<record::ProtocolVersion>() + size_of::<record::Epoch>() + size_of::<record::SequenceNumber>();
    let mut n = 0;
    let mut records: Vec<Vec<u8>> = Vec::new();
    while n < buf.len() {
        let length = BigEndian::read_u16(&buf[n + length_offset..n + length_offset + 2]) as usize + length_offset + size_of::<record::Length>();
        records.push(buf[n..n + length].to_vec());
        n += length;
    }
    records
}
