use crate::errors;
use crate::handshake;
use crate::pack::Pack;
use crate::record;

use std::collections::BTreeMap;

/// Given a bunch of already sorted records, returns a reassembled handshake message with the record layer stripped
pub fn reassemble_handshake(
    fragmented_records: BTreeMap<(record::Epoch, record::SequenceNumber, handshake::MessageSeq), Vec<u8>>,
) -> Result<Vec<u8>, errors::DTLSError> {
    // TODO if MessageSeqs or epochs all not equal, defensively fail
    match fragmented_records.len() {
        0 => Err(errors::DTLSError::InvalidLengthError), // TODO better error
        1 => {
            Ok(fragmented_records.iter().next().ok_or_else(|| errors::DTLSError::InvalidLengthError)?.1[handshake::HANDSHAKE_TYPE_OFFSET..].to_vec())
        }
        _ => {
            // TODO if other fields, like fragment length, not all the same, defensively fail
            // Can keep fragment offset but will need to update fragment length

            // For hashing handshake, reassemble as if it were a single fragment (fragment_offset = 0, fragment_length = handshake_length)
            let mut iter = fragmented_records.iter();
            let mut record = iter.next().ok_or_else(|| errors::DTLSError::InvalidLengthError)?.1.clone();
            let total_handshake_length = handshake::handshake_length_from_record(record.clone())?;
            record = [
                record[handshake::HANDSHAKE_TYPE_OFFSET..handshake::FRAGMENT_LENGTH_OFFSET].to_vec(),
                total_handshake_length.pack(),
                record[handshake::HANDSHAKE_BODY_OFFSET..].to_vec(),
            ]
            .concat();

            while let Some(fragmented) = iter.next() {
                record.extend_from_slice(&fragmented.1.clone()[handshake::HANDSHAKE_BODY_OFFSET..]);
            }

            Ok(record)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::fragment;
    use crate::handshake;
    use crate::pack::Pack;
    use crate::record;

    use hex;
    use std::collections::BTreeMap;

    #[test]
    fn reassemble_handshake_certificate() {
        let fragment1 = hex::decode("16fefd0000000000000002007d0b000375000200000000007100037200036f3082036b30820253a00302010202142ba3f51616425cc96c64929985278c72b67be919300d06092a864886f70d01010b05003045310b30090603550406130255533113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e65742057")
            .expect("decode fragment1 failed");
        let fragment2 = hex::decode("16fefd000000000000000300d70b00037500020000710000cb69646769747320507479204c7464301e170d3230303330353138323831385a170d3330303330333138323831385a3045310b30090603550406130255533113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c746430820122300d06092a864886f70d01010105000382010f003082010a0282010100e362aa506b8af8e6c3ae959a352cbb4519e67943ca61964b6e21c6c5ac901c410966a43dc7a761ec562f377b7a1bdfe3b6424cad0b")
            .expect("decode fragment2 failed");
        let fragment3 = hex::decode("16fefd000000000000000400d70b000375000200013c0000cbe59ae7317e7602a8c26e7bd387349e00c00523d0fee737dd35ad0be5ba39ab0943a999745a1ffccb61e253b11737472cde658023f7df84887db7a4863e18d30768a27941f16e341690e4248701e6611b6dd9aee24c2018ec975916254eb6069444505b61a881364cf996e30453e9a4bcc9abc06d4b676af82681e528fa63a225d0eda98d9fe27165741bc5cc32e7da109de3a97a6b0d941ea4dc10431f2a3a720752a3e6e27e3787ae0555a5ba35276a08840b1654c14b5542698891c42c60cb825a72398333e014275e6d")
            .expect("decode fragment2 failed");
        let fragment4 = hex::decode("16fefd000000000000000500d70b00037500020002070000cb0203010001a3533051301d0603551d0e04160414790f21d253cedb23fed7572e41f0f78656fcac4e301f0603551d23041830168014790f21d253cedb23fed7572e41f0f78656fcac4e300f0603551d130101ff040530030101ff300d06092a864886f70d01010b05000382010100bb2932a8f469f37a18b22b3ad13a8dae2b3556b9c262688453260747db53d7f14941b10c79da0374e2c9db924cad53c192b5f9ad34a5b502034f30cbf4e4d5691d8bbf675dbf316d6aafbbd98c8667b41ad2102e15c045ad1fcdf9625c")
            .expect("decode fragment2 failed");
        let fragment5 = hex::decode("16fefd000000000000000600af0b00037500020002d20000a3c993a28ed2dd48d0775cebb85019db238d2ad924887aeb47142d7a5f4d8e279b84e2cfbb9326fc8d768156b7960824d09ea0068b30db19a669bf47524002afc45f293f0427c75ab474bbf679891879aa120c2409d03e52bb2fa2d57fd3e27dc03e471127f4d310b96536d0f05d0d71c86abfc7847e3252e25d44a1f44cd99dc65d5fa6c560d7b819bfbf984ffec8aa0109dc0ad02ebfb75fb46ffe476a55ed4394f0b3")
            .expect("decode fragment2 failed");

        let records = vec![fragment1, fragment2, fragment3, fragment4, fragment5];
        let mut fragments: BTreeMap<(record::Epoch, record::SequenceNumber, handshake::MessageSeq), Vec<u8>> = BTreeMap::new();
        for record in records {
            let id = (
                record::epoch_from_record(record.clone()),
                record::sequence_number_from_record(record.clone()).expect("sequence_number_from_record failed"),
                handshake::message_seq_from_record(record.clone()).expect("message_seq_from_record failed"),
            );
            fragments.insert(id, record.clone());
        }

        let mut reassembled_certificate_bytes = fragment::reassemble_handshake(fragments).expect("reassemble handshake failed");

        let mut certificates_handshake = handshake::Handshake::<handshake::Certificates>::empty();
        let _ = certificates_handshake.unpack(&mut reassembled_certificate_bytes);

        let certificates_hex = "00037200036f3082036b30820253a00302010202142ba3f51616425cc96c64929985278c72b67be919300d06092a864886f70d01010b05003045310b30090603550406130255533113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c7464301e170d3230303330353138323831385a170d3330303330333138323831385a3045310b30090603550406130255533113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c746430820122300d06092a864886f70d01010105000382010f003082010a0282010100e362aa506b8af8e6c3ae959a352cbb4519e67943ca61964b6e21c6c5ac901c410966a43dc7a761ec562f377b7a1bdfe3b6424cad0be59ae7317e7602a8c26e7bd387349e00c00523d0fee737dd35ad0be5ba39ab0943a999745a1ffccb61e253b11737472cde658023f7df84887db7a4863e18d30768a27941f16e341690e4248701e6611b6dd9aee24c2018ec975916254eb6069444505b61a881364cf996e30453e9a4bcc9abc06d4b676af82681e528fa63a225d0eda98d9fe27165741bc5cc32e7da109de3a97a6b0d941ea4dc10431f2a3a720752a3e6e27e3787ae0555a5ba35276a08840b1654c14b5542698891c42c60cb825a72398333e014275e6d0203010001a3533051301d0603551d0e04160414790f21d253cedb23fed7572e41f0f78656fcac4e301f0603551d23041830168014790f21d253cedb23fed7572e41f0f78656fcac4e300f0603551d130101ff040530030101ff300d06092a864886f70d01010b05000382010100bb2932a8f469f37a18b22b3ad13a8dae2b3556b9c262688453260747db53d7f14941b10c79da0374e2c9db924cad53c192b5f9ad34a5b502034f30cbf4e4d5691d8bbf675dbf316d6aafbbd98c8667b41ad2102e15c045ad1fcdf9625cc993a28ed2dd48d0775cebb85019db238d2ad924887aeb47142d7a5f4d8e279b84e2cfbb9326fc8d768156b7960824d09ea0068b30db19a669bf47524002afc45f293f0427c75ab474bbf679891879aa120c2409d03e52bb2fa2d57fd3e27dc03e471127f4d310b96536d0f05d0d71c86abfc7847e3252e25d44a1f44cd99dc65d5fa6c560d7b819bfbf984ffec8aa0109dc0ad02ebfb75fb46ffe476a55ed4394f0b3";
        let certificates_bytes = hex::decode(certificates_hex).expect("decode certificates hex failed");
        assert_eq!(certificates_handshake.body.pack(), certificates_bytes);
    }
}
