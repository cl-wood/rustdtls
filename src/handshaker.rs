use crate::cipher;
use crate::errors;
use crate::extensions;
use crate::fields;
use crate::handshake;
use crate::record;

use ring::agreement::PublicKey;
use ring::rand;

pub fn client_hello(
    rand: &dyn rand::SecureRandom,
    cookie: handshake::Cookie,
    message_seq: handshake::MessageSeq,
) -> Result<handshake::Handshake<handshake::ClientHello>, errors::DTLSError> {
    let random = handshake::Random::new(rand)?;
    let session_id = handshake::SessionID::new(Vec::new())?;

    let mut cipher_suites_vec: Vec<fields::Uint16> = Vec::new();

    cipher_suites_vec.push(cipher::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
    cipher_suites_vec.push(cipher::TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

    let cipher_suites = handshake::CipherSuites::new(cipher_suites_vec)?;
    let compression_method_vec: Vec<handshake::CompressionMethod> = vec![handshake::CompressionMethod::Null];
    let compression_methods = handshake::CompressionMethods::new(compression_method_vec)?;

    let extensions = vec![
        extensions::ec_point_formats(),
        extensions::supported_groups(),
        extensions::encrypt_then_mac(),
    ];
    let client_hello_extension_list = extensions::ClientHelloExtensionList::new(extensions);

    let client_hello = handshake::ClientHello {
        client_version: record::DTLS_1_2,
        random,
        session_id,
        cookie,
        cipher_suites,
        compression_methods,
        client_hello_extension_list,
    };

    // NOTE TODO in unfragmented messages, length = fragment_length
    // In the future, will need to handle fragmentation. length is the length of the total, unfragmented packet, each fragment gives its offset in the total
    // and the local length of itself
    handshake::Handshake::new(message_seq, client_hello)
}

pub fn hello_verify_request() -> Result<handshake::Handshake<handshake::HelloVerifyRequest>, errors::DTLSError> {
    // TODO For now, borrow OpenSSL len 20 cookie. In future need to generate our own, probably based off server and client info
    //      RFC mentions one way is: Cookie = HMAC(Secret, Client-IP, Client-Parameters)
    let cookie = vec![
        20, 0x1c, 0x8f, 0x37, 0xcc, 0x94, 0x00, 0xa4, 0x39, 0x65, 0x0d, 0xc2, 0x1d, 0xf5, 0xe9, 0xd1, 0x1a, 0x73, 0x17, 0x33, 0x69,
    ];
    let cookie = handshake::Cookie::new(cookie)?;
    let hello_verify_request = handshake::HelloVerifyRequest {
        server_version: record::DTLS_1_2,
        cookie,
    };
    handshake::Handshake::new(fields::Uint16(0), hello_verify_request)
}

pub fn client_key_exchange(
    message_seq: handshake::MessageSeq,
    pub_key: &PublicKey,
) -> Result<handshake::Handshake<handshake::ClientKeyExchange>, errors::DTLSError> {
    let client_key_exchange = handshake::ClientKeyExchange::new(pub_key.as_ref().to_vec())?;
    handshake::Handshake::new(message_seq, client_key_exchange)
}

pub fn finished(message_seq: handshake::MessageSeq, verify_data: Vec<u8>) -> Result<handshake::Handshake<handshake::Finished>, errors::DTLSError> {
    let finished = handshake::Finished::new(verify_data);
    handshake::Handshake::new(message_seq, finished)
}

#[cfg(test)]
mod tests {
    use crate::crypto;
    use crate::fields;
    use crate::handshaker;
    use crate::pack::Pack;
    use crate::pack_unpack_inverse_test;

    /*
    pack_unpack_inverse_test!(
        handshake_client_hello_pack_unpack_inverse_test,
        handshaker::client_hello(
            &rand::SystemRandom::new(),
            handshake::Cookie::new(Vec::new()).expect("building cookie failed"),
            fields::Uint16(0),
        )
        .expect("building Handshake<ClientHello> failed")
    );*/
    pack_unpack_inverse_test!(
        handshake_hello_verify_request_pack_unpack_inverse_test,
        handshaker::hello_verify_request().expect("building Handshake<HelloVerifyRequest> failed")
    );

    pack_unpack_inverse_test!(
        handshake_client_key_exchange_pack_unpack_inverse_test,
        handshaker::client_key_exchange(fields::Uint16(0), &crypto::ephemeral_keys().expect("ephemeral_keys failed").0)
            .expect("building Handshake<HelloVerifyRequest> failed")
    );
}
