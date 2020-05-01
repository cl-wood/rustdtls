use crate::change_cipher_spec;
use crate::crypto;
use crate::errors;
use crate::fields;
use crate::handshake;
use crate::handshaker;
use crate::record::DTLSPlaintext_change_cipher_spec;
use crate::record::{BlockCiphered, ContentType, DTLSCiphertext, DTLSPlaintext, Epoch, GenericBlockCipher, SequenceNumber, DTLS_1_2};

use ring::agreement::PublicKey;
use ring::rand;

pub struct Dtls {}

impl Dtls {
    pub fn client_hello(
        rand: &rand::SystemRandom,
        cookie: handshake::Cookie,
        message_seq: handshake::MessageSeq,
        epoch: Epoch,
        sequence_number: SequenceNumber,
    ) -> Result<DTLSPlaintext<handshake::ClientHello>, errors::DTLSError> {
        let handshake = handshaker::client_hello(rand, cookie, message_seq)?;
        let msg = DTLSPlaintext::new(ContentType::Handshake, DTLS_1_2, epoch, sequence_number, handshake)?;
        Ok(msg)
    }

    #[allow(dead_code)]
    pub fn hello_verify_request(
        epoch: Epoch,
        sequence_number: SequenceNumber,
    ) -> Result<DTLSPlaintext<handshake::HelloVerifyRequest>, errors::DTLSError> {
        let handshake = handshaker::hello_verify_request()?;
        let msg = DTLSPlaintext::new(ContentType::Handshake, DTLS_1_2, epoch, sequence_number, handshake)?;
        Ok(msg)
    }

    pub fn client_key_exchange(
        message_seq: handshake::MessageSeq,
        epoch: Epoch,
        sequence_number: SequenceNumber,
        pub_key: &PublicKey,
    ) -> Result<DTLSPlaintext<handshake::ClientKeyExchange>, errors::DTLSError> {
        let handshake = handshaker::client_key_exchange(message_seq, pub_key)?;
        let msg = DTLSPlaintext::new(ContentType::Handshake, DTLS_1_2, epoch, sequence_number, handshake)?;
        Ok(msg)
    }

    pub fn change_cipher_spec(epoch: Epoch, sequence_number: SequenceNumber) -> Result<DTLSPlaintext_change_cipher_spec, errors::DTLSError> {
        let change_cipher_spec = change_cipher_spec::ChangeCipherSpec {
            r#type: change_cipher_spec::Type::ChangeCipherSpec,
        };
        let msg = DTLSPlaintext_change_cipher_spec {
            r#type: ContentType::ChangeCipherSpec,
            version: DTLS_1_2,
            epoch,
            sequence_number,
            length: fields::Uint16(1),
            change_cipher_spec,
        };
        Ok(msg)
    }

    pub fn finished(
        message_seq: handshake::MessageSeq,
        epoch: Epoch,
        sequence_number: SequenceNumber,
        verify_data: Vec<u8>,
        security_parameters: &crypto::SecurityParameters,
        key_block: &crypto::KeyBlock,
    ) -> Result<DTLSCiphertext, errors::DTLSError> {
        let handshake = handshaker::finished(message_seq, verify_data)?;
        let plaintext = DTLSPlaintext::new(ContentType::Handshake, DTLS_1_2, epoch, sequence_number, handshake)?;
        DTLSCiphertext::from_dtls_plaintext(plaintext, security_parameters, key_block)
    }

    pub fn application_data(
        epoch: Epoch,
        sequence_number: SequenceNumber,
        data: &[u8],
        security_parameters: &crypto::SecurityParameters,
    ) -> Result<DTLSCiphertext, errors::DTLSError> {
        // TODO match cipher on security params
        let block_ciphered = BlockCiphered::new(data.to_vec(), None, security_parameters.cipher_parameters.block_length.0 as usize);
        let generic_block_cipher = GenericBlockCipher::new(block_ciphered);

        let msg = DTLSCiphertext::new(ContentType::ApplicationData, DTLS_1_2, epoch, sequence_number, generic_block_cipher)?;
        Ok(msg)
    }
}

// TODO test for, example, each possible error in client_hello

#[cfg(test)]
mod tests {
    /*
    pack_unpack_inverse_test!(
        dtls_handshake_client_hello_pack_unpack_inverse_test,
        dtls::Dtls::new()
            .client_hello(
                handshake::Cookie::new(Vec::new()).expect("building cookie failed"),
                fields::Uint16(0),
                fields::Uint16(0),
                fields::Uint48([0; 6])
            )
            .expect("building DtlsClientHello failed")
    );*/
}
