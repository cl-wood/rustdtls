use crate::cipher;
use crate::errors;
use crate::fields;
use crate::handshake;
use crate::pack::Pack;
use crate::record::{ContentType, Epoch, ProtocolVersion, SequenceNumber};

use aes::Aes256;
use block_modes::block_padding::{NoPadding, Pkcs7};
use block_modes::{BlockMode, Cbc};
use ring::agreement::{EphemeralPrivateKey, PublicKey, X25519};
//use ring::error::Unspecified;
use ring::hmac;
use sha2::{Digest, Sha256};

pub const VERIFY_DATA_LENGTH: usize = 12; // Default
pub const MASTER_SECRET_STR: &[u8; 13] = b"master secret";
pub const MASTER_SECRET_LEN: usize = 48;
#[allow(dead_code)]
pub const EXTENDED_MASTER_SECRET_STR: &[u8; 22] = b"extended master secret";

pub const KEY_BLOCK_STR: &[u8; 13] = b"key expansion";

pub type MasterSecret = [u8; MASTER_SECRET_LEN];

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ConnectionEnd {
    #[allow(dead_code)]
    Server,
    Client,
}

#[derive(Clone, Copy)]
pub struct HandshakeParameters {
    pub master_secret: MasterSecret,
    pub client_random: handshake::Random,
    pub server_random: handshake::Random,
}

// TODO this is actually an impl of Diffie-Hellman handshake params, make generic later
impl HandshakeParameters {
    pub fn new(pre_master_secret: &[u8], client_random: handshake::Random, server_random: handshake::Random) -> Result<Self, errors::DTLSError> {
        //let pre_master_secret = pre_master_secret(diffie_hellman, their_pub_key);
        let master_secret = master_secret(pre_master_secret, client_random, server_random)?;
        Ok(Self {
            master_secret,
            client_random,
            server_random,
        })
    }
}

#[derive(Clone)]
pub struct SecurityParameters {
    pub entity: ConnectionEnd,
    pub cipher_parameters: cipher::CipherParameters,
    pub compression_algorithm: handshake::CompressionMethod,
    pub handshake_parameters: HandshakeParameters,
}

impl SecurityParameters {
    pub fn new(
        entity: ConnectionEnd,
        cipher_name: cipher::CipherName,
        compression_algorithm: handshake::CompressionMethod,
        handshake_parameters: HandshakeParameters,
    ) -> Result<Self, errors::DTLSError> {
        Ok(Self {
            entity,
            cipher_parameters: cipher::parameters(cipher_name)?,
            compression_algorithm,
            handshake_parameters,
        })
    }
}

#[derive(Clone)]
pub struct KeyBlock {
    pub client_write_mac_key: Vec<u8>,
    pub server_write_mac_key: Vec<u8>,
    pub client_write_key: Vec<u8>,
    pub server_write_key: Vec<u8>,
    client_write_iv: Vec<u8>, // Only used for AEAD
    server_write_iv: Vec<u8>, // Only used for AEAD
}

impl KeyBlock {
    pub fn new(security_parameters: SecurityParameters) -> Result<Self, errors::DTLSError> {
        let mac_key_length = security_parameters.cipher_parameters.mac_key_length.0 as usize;
        let write_key_length = security_parameters.cipher_parameters.enc_key_length.0 as usize;
        let write_iv_length = security_parameters.cipher_parameters.fixed_iv_length.0 as usize;
        let total_length = mac_key_length * 2 + write_key_length * 2 + write_iv_length * 2;

        let seed = &[
            security_parameters.handshake_parameters.server_random.pack(),
            security_parameters.handshake_parameters.client_random.pack(),
        ]
        .concat()[..];
        let unparsed_block = call_prf(total_length, &security_parameters.handshake_parameters.master_secret, KEY_BLOCK_STR, seed)?;

        let mut i = 0;
        let client_write_mac_key = unparsed_block[i..i + mac_key_length].to_vec();
        i += mac_key_length;
        let server_write_mac_key = unparsed_block[i..i + mac_key_length].to_vec();
        i += mac_key_length;
        let client_write_key = unparsed_block[i..i + write_key_length].to_vec();
        i += write_key_length;
        let server_write_key = unparsed_block[i..i + write_key_length].to_vec();
        i += write_key_length;
        let client_write_iv = unparsed_block[i..i + write_iv_length].to_vec();
        i += write_iv_length;
        let server_write_iv = unparsed_block[i..i + write_iv_length].to_vec();
        Ok(Self {
            client_write_mac_key,
            server_write_mac_key,
            client_write_key,
            server_write_key,
            client_write_iv,
            server_write_iv,
        })
    }
}

// TODO from rustls
pub fn ephemeral_keys() -> Result<(PublicKey, EphemeralPrivateKey), errors::DTLSError> {
    let rng = ring::rand::SystemRandom::new();
    let our_private_key = EphemeralPrivateKey::generate(&X25519, &rng).map_err(|_| errors::DTLSError::UnspecifiedRingError)?;
    let our_pubkey = our_private_key
        .compute_public_key()
        .map_err(|_| errors::DTLSError::UnspecifiedRingError)?;
    Ok((our_pubkey, our_private_key))
}

pub fn shared_secret(our_private_key: EphemeralPrivateKey, their_pub_key_bytes: &[u8]) -> Result<Vec<u8>, errors::DTLSError> {
    let their_pub_key = ring::agreement::UnparsedPublicKey::new(&X25519, their_pub_key_bytes);
    let shared_secret = ring::agreement::agree_ephemeral(our_private_key, &their_pub_key, (), |result| Ok(result.to_vec()))
        .map_err(|_| errors::DTLSError::UnspecifiedRingError)?;

    Ok(shared_secret)
}

pub fn mac(
    security_parameters: &SecurityParameters,
    key_block: &KeyBlock,
    epoch: Epoch,
    seq_num: SequenceNumber,
    r#type: ContentType,
    version: ProtocolVersion,
    iv: &[u8],
    fragment: &[u8],
) -> Result<Vec<u8>, errors::DTLSError> {
    // TODO mac length would be included if not encrypt-then-mac?
    //let length = fields::Uint16((iv.len() + fragment.len() + security_parameters.cipher_parameters.mac_length.0 as usize) as u16);
    let length = fields::Uint16((iv.len() + fragment.len()) as u16);

    let material = &[
        epoch.pack(),
        seq_num.pack(),
        r#type.pack(),
        version.pack(),
        length.pack(),
        iv.to_vec(),
        fragment.to_vec(),
    ]
    .concat()[..];

    let write_mac_key = match security_parameters.entity {
        ConnectionEnd::Client => &key_block.client_write_mac_key,
        ConnectionEnd::Server => &key_block.server_write_mac_key,
    };
    let algorithm = match security_parameters.cipher_parameters.mac_algorithm {
        cipher::MACAlgorithm::HmacSha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        _ => {
            return Err(errors::DTLSError::MACAlgorithmNotSupportedError(
                security_parameters.cipher_parameters.mac_algorithm,
            ))
        }
    };

    let key = hmac::Key::new(algorithm, write_mac_key);
    Ok(hmac::sign(&key, material).as_ref().to_vec())
}

//master_secret = PRF(pre_master_secret, "master secret", ClientHello.random + ServerHello.random)[0..47];
pub fn master_secret(
    pre_master_secret: &[u8],
    client_hello_random: handshake::Random,
    server_hello_random: handshake::Random,
) -> Result<MasterSecret, errors::DTLSError> {
    let seed = &[client_hello_random.pack(), server_hello_random.pack()].concat()[..];
    let result = call_prf(MASTER_SECRET_LEN, pre_master_secret, MASTER_SECRET_STR, seed)?;

    let mut master_secret = [0; MASTER_SECRET_LEN];
    let bytes = &result[..master_secret.len()]; // panics if not enough data
    master_secret.copy_from_slice(bytes);
    Ok(master_secret)
}

#[allow(dead_code)]
pub fn extended_master_secret(_pre_master_secret: Vec<u8>, _session_hash: Vec<u8>) -> Result<(), errors::DTLSError> {
    /*let mut result = pseudo_random_function(&pre_master_secret[..], EXTENDED_MASTER_SECRET_STR, &session_hash)?;
    while result.len() < MASTER_SECRET_LEN {
        result.extend_from_slice(&pseudo_random_function(&pre_master_secret[..], b"", &result.clone()[..])?[..]);
    }

    let mut extended_master_secret = [0; MASTER_SECRET_LEN];
    let bytes = &result[..extended_master_secret.len()]; // panics if not enough data
    extended_master_secret.copy_from_slice(bytes);
    Ok(extended_master_secret)*/
    Ok(())
}

// TODO borrowed from rustls
fn concat_sign(key: &hmac::Key, a: &[u8], b: &[u8]) -> hmac::Tag {
    let mut ctx = hmac::Context::with_key(key);
    ctx.update(a);
    ctx.update(b);
    ctx.sign()
}

// TODO no failable calls here, return a Vec<u8>
pub fn call_prf(output_length: usize, secret: &[u8], label: &[u8], seed: &[u8]) -> Result<Vec<u8>, errors::DTLSError> {
    // A(0) = seed
    // A(i) = HMAC_hash(secret, A(i-1))
    let a_0 = &[label, seed].concat();
    // A(1) = HMAC_hash(secret, A(0))
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let a_1 = hmac::sign(&key, a_0);

    // HMAC_hash(secret, A(1) + seed)
    let p_hash = concat_sign(&key, a_1.as_ref(), a_0);
    let mut result = p_hash.as_ref().to_vec();

    let mut a_prev = a_1;
    while result.len() < output_length {
        // HMAC_hash(secret, A(n-1) + seed)
        a_prev = hmac::sign(&key, a_prev.as_ref());
        let p_hash = concat_sign(&key, a_prev.as_ref(), a_0);
        result.extend_from_slice(p_hash.as_ref());
    }
    Ok(result[..output_length].to_vec())
}

pub fn verify_data(master_secret: MasterSecret, finished_label: &[u8], handshake_messages: Vec<u8>) -> Result<Vec<u8>, errors::DTLSError> {
    let mut hash = Sha256::new();
    hash.input(handshake_messages);
    let handshake_hash = hash.result();
    let prf_output = call_prf(VERIFY_DATA_LENGTH, &master_secret, finished_label, &handshake_hash)?;
    Ok(prf_output[..VERIFY_DATA_LENGTH].to_vec())
}

pub fn create_verify_data(
    shared_secret: &[u8],
    client_hello_random: handshake::Random,
    server_hello_random: handshake::Random,
    finished_label: &[u8],
    handshake_messages: Vec<u8>,
) -> Result<Vec<u8>, errors::DTLSError> {
    let master_secret = master_secret(shared_secret, client_hello_random, server_hello_random)?;
    let verify_data = verify_data(master_secret, finished_label, handshake_messages)?;
    Ok(verify_data)
}

/*
pub fn encrypt(
    iv: Vec<u8>,
    plaintext: Vec<u8>,
    shared_secret: Vec<u8>, // TODO master_secret? client_write_key?
    _security_parameters: SecurityParameters,
    _key_block: KeyBlock,
) -> Result<Vec<u8>, errors::DTLSError> {
    // TODO only if encrypt-then-mac extension enabled
    // TODO encrypt from encrypt_then_mac, which works

    //let shared_secret = pre_master_secret(dh, their_pub_key);
    //let key = shared_secret.as_bytes();
    let key = shared_secret;

    //type Aes256Cbc = Cbc<Aes256, Pkcs7>;
    //let cipher = Aes256Cbc::new_var(&key[..], &iv)?;

    let ciphertext = cipher.encrypt_vec(&plaintext[..]);
    Ok(ciphertext)
}*/

pub fn encrypt_then_mac(
    iv: &[u8],
    plaintext: Vec<u8>,
    security_parameters: &SecurityParameters,
    key_block: &KeyBlock,
    epoch: Epoch,
    seq_num: SequenceNumber,
    r#type: ContentType,
    version: ProtocolVersion,
) -> Result<Vec<u8>, errors::DTLSError> {
    // TODO match on security_parameters

    type Aes256Cbc = Cbc<Aes256, NoPadding>;
    let cipher = Aes256Cbc::new_var(&key_block.client_write_key, &iv)?;

    let ciphertext = &cipher.encrypt_vec(&plaintext);
    let mac = mac(&security_parameters, &key_block, epoch, seq_num, r#type, version, &iv, &ciphertext)?;
    Ok([iv, ciphertext, &mac].concat())
}

pub fn decrypt(
    iv: &[u8],
    ciphertext: &[u8],
    mac: &[u8],
    security_parameters: &SecurityParameters,
    key_block: &KeyBlock,
) -> Result<Vec<u8>, errors::DTLSError> {
    type Aes256Cbc = Cbc<Aes256, NoPadding>;
    let cipher = Aes256Cbc::new_var(&key_block.server_write_key, &iv)?;

    println!("IV: len({}), {:x?}", iv.len(), iv);
    println!("Ciphertext: len({}), {:x?}", ciphertext.len(), ciphertext);
    println!("MAC: len({}), {:x?}", mac.len(), mac);

    let plaintext = &cipher.decrypt_vec(&ciphertext)?;
    println!("Plaintext: {:x?}", plaintext);

    Ok(plaintext.clone())
}

#[cfg(test)]
mod tests {
    use crate::cipher;
    use crate::crypto;
    use crate::dtls;
    use crate::fields;
    use crate::handshake;
    use crate::pack::Pack;

    use hex;

    // TODO cannot test re-creating master secret from wireshark, ephemeral secret never sent over wire and can't find a way to get OpenSSL to spit it outs

    /// Using network traffic from ground_truth.pcapng, test that we generate verify_data correctly
    #[test]
    fn verify_data() {
        let mut master_secret = [0; crypto::MASTER_SECRET_LEN];
        let bytes = &hex::decode("955912e660b8e7508e1585ac725c9dd39c7b3754412a163b714de1726331f738ca414530abdf37dc8b58588f71a7c636")
            .expect("decode master secret failed");
        master_secret.copy_from_slice(bytes);

        //  Handshakes messages from wireshark hexstreams
        let mut handshake_messages = Vec::new();

        // Don't include initial ClientHello and HelloVerifyRequest with cookies in verify_data

        // TODO TODO deal with extensions, probably by modifying Pack trait
        let client_hello_bytes = hex::decode("010000910001000000000091fefdc821f155aeafa616f4f942faede721055f1a21467ae21934938730f16f479c7e0001490004c01400ff01000062000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000016000000170000000d0030002e040305030603080708080809080a080b080408050806040105010601030302030301020103020202040205020602")
            .expect("ClientHello decode failed");
        //let mut client_hello = handshake::Handshake::<handshake::ClientHello>::empty();
        //let _ = client_hello.unpack(&mut client_hello_bytes.clone());
        //handshake_messages.extend_from_slice(&client_hello.pack());
        //println!("ClientHello pack = {:?}", client_hello.pack());
        //println!("ClientHello bytes = {:?}", client_hello_bytes);
        handshake_messages.extend_from_slice(&client_hello_bytes);

        let server_hello_bytes = hex::decode("020000410001000000000041fefd796250e4584a5946a99c8d64078a7e26213a5dc0140f644310d8744cda25434500c014000019ff01000100000b000403000102002300000016000000170000")
            .expect("ServerHello decode failed");
        //let mut server_hello = handshake::Handshake::<handshake::ServerHello>::empty();
        //let _ = server_hello.unpack(&mut server_hello_bytes);
        //handshake_messages.extend_from_slice(&server_hello.pack());
        handshake_messages.extend_from_slice(&server_hello_bytes);

        let mut server_certificate_bytes = hex::decode(
            concat!(
                "0b",
                "000375",
                "0002",
                "00d2d2",
                "0000a3",
                "00037200036f3082036b30820253a00302010202142ba3f51616425cc96c64929985278c72b67be919300d06092a864886f70d01010b05003045310b30090603550406130255533113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c7464301e170d3230303330353138323831385a170d3330303330333138323831385a3045310b30090603550406130255533113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c746430820122300d06092a864886f70d01010105000382010f003082010a0282010100e362aa506b8af8e6c3ae959a352cbb4519e67943ca61964b6e21c6c5ac901c410966a43dc7a761ec562f377b7a1bdfe3b6424cad0be59ae7317e7602a8c26e7bd387349e00c00523d0fee737dd35ad0be5ba39ab0943a999745a1ffccb61e253b11737472cde658023f7df84887db7a4863e18d30768a27941f16e341690e4248701e6611b6dd9aee24c2018ec975916254eb6069444505b61a881364cf996e30453e9a4bcc9abc06d4b676af82681e528fa63a225d0eda98d9fe27165741bc5cc32e7da109de3a97a6b0d941ea4dc10431f2a3a720752a3e6e27e3787ae0555a5ba35276a08840b1654c14b5542698891c42c60cb825a72398333e014275e6d0203010001a3533051301d0603551d0e04160414790f21d253cedb23fed7572e41f0f78656fcac4e301f0603551d23041830168014790f21d253cedb23fed7572e41f0f78656fcac4e300f0603551d130101ff040530030101ff300d06092a864886f70d01010b05000382010100bb2932a8f469f37a18b22b3ad13a8dae2b3556b9c262688453260747db53d7f14941b10c79da0374e2c9db924cad53c192b5f9ad34a5b502034f30cbf4e4d5691d8bbf675dbf316d6aafbbd98c8667b41ad2102e15c045ad1fcdf9625cc993a28ed2dd48d0775cebb85019db238d2ad924887aeb47142d7a5f4d8e279b84e2cfbb9326fc8d768156b7960824d09ea0068b30db19a669bf47524002afc45f293f0427c75ab474bbf679891879aa120c2409d03e52bb2fa2d57fd3e27dc03e471127f4d310b96536d0f05d0d71c86abfc7847e3252e25d44a1f44cd99dc65d5fa6c560d7b819bfbf984ffec8aa0109dc0ad02ebfb75fb46ffe476a55ed4394f0b3"
            )
        ).expect("Certificates decode failed");
        let mut server_certificate = handshake::Handshake::<handshake::Certificates>::empty();
        let _ = server_certificate.unpack(&mut server_certificate_bytes);
        handshake_messages.extend_from_slice(
            &server_certificate
                .fix_reassembled_lengths()
                .expect("Certificates fix_reassembled_lengths failed")
                .pack(),
        );

        let mut server_key_exchange_bytes = hex::decode(
            concat!(
                "0c",
                "000128",
                "0003",
                "000000", // fragment_offset, was originally "0000da"
                "000128", // fragment_length, was originally "00004e"
                "03001d20b29f3841ac2f628fb51cd8fef4d5ebbdf6227f6e69e85b67a55f5084aec5823d080401005bc6ff99552903b010045ef458ee8bb75ce2b63bda685a4e54136f4f6e0687984162fdb0bff0335d44adc5fe7110e4396342bacefda9058645f7ab4feb748047dc3eb996f64d91284877669ba8eecef4d3c080a1740c543f427537eae3f284108bd3d7e924826e9d42a68181a51d5e922cbd01423ca4e4ac7f5f96e5559547ffca188825c95a8812ff817bb6476f79b945f5be7f9130379e682f0c57be0d2120b8a8c9a82f41a13726355e8c81cb3d0f3e2d9fe2a3a07a6527426efdb3bfea56c6396cc97470ef33458a06e1c17cb6200388ab0800e498edf2f8d05aaefe28966c3ca1d1612cfce2a8696e39f99ce50f0c67c3368edb8b6d6bedd0c4a6bf827b",
            )
        ).expect("ServerKeyExchange decode failed");

        let mut server_key_exchange = handshake::Handshake::<handshake::ServerKeyExchangeExtended>::empty();
        let _ = server_key_exchange.unpack(&mut server_key_exchange_bytes);
        handshake_messages.extend_from_slice(
            &server_key_exchange
                .fix_reassembled_lengths()
                .expect("ServerKeyExchange fix_reassembled_lengths failed")
                .pack(),
        );
        //handshake_messages.extend_from_slice(&server_key_exchange_bytes);

        let mut server_hello_done_bytes = hex::decode("0e0000000004000000000000").expect("ServerHelloDone decode failed");
        let mut server_hello_done = handshake::Handshake::<handshake::ServerHelloDone>::empty();
        let _ = server_hello_done.unpack(&mut server_hello_done_bytes);
        handshake_messages.extend_from_slice(&server_hello_done.pack());
        //handshake_messages.extend_from_slice(&server_hello_done_bytes);

        let mut client_key_exchange_bytes = hex::decode("10000021000200000000002120c6ad5d485d1d0068109d3b3c23a1e42c9bb8b14ff7eacf9a50a8ec9a7a97e73b")
            .expect("ClientKeyExchange decode failed");
        let mut client_key_exchange = handshake::Handshake::<handshake::ClientKeyExchange>::empty();
        let _ = client_key_exchange.unpack(&mut client_key_exchange_bytes);
        handshake_messages.extend_from_slice(&client_key_exchange.pack());
        //handshake_messages.extend_from_slice(&client_key_exchange_bytes);

        // TODO here's our test. TODO check server finished also
        // Check finished message against ground truth
        let client_verify_data =
            crypto::verify_data(master_secret, handshake::CLIENT_FINISHED_LABEL, handshake_messages).expect("verify_data failed");
        let expected_client_verify_data = hex::decode("015219c3d3e1ea9f4fce24a2").expect("client_verify_data decode failed");
        assert_eq!(client_verify_data, expected_client_verify_data);

        // Build finished message and check against ground truth
        let mut client_random_bytes =
            hex::decode("c821f155aeafa616f4f942faede721055f1a21467ae21934938730f16f479c7e").expect("decode client random failed");
        let mut client_random = handshake::Random::empty();
        let _ = client_random.unpack(&mut client_random_bytes);
        let mut server_random_bytes =
            hex::decode("796250e4584a5946a99c8d64078a7e26213a5dc0140f644310d8744cda254345").expect("decode server random failed");
        let mut server_random = handshake::Random::empty();
        let _ = server_random.unpack(&mut server_random_bytes);
        let handshake_parameters = crypto::HandshakeParameters {
            master_secret,
            client_random,
            server_random,
        };
        let security_parameters = crypto::SecurityParameters::new(
            crypto::ConnectionEnd::Client,
            cipher::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            handshake::CompressionMethod::Null,
            handshake_parameters,
        )
        .expect("SecurityParameters failed");
        let key_block = crypto::KeyBlock::new(security_parameters.clone()).expect("building KeyBlock failed");

        let finished = dtls::Dtls::finished(
            fields::Uint16(3),
            fields::Uint16(1),
            fields::Uint48([0; 6]),
            client_verify_data,
            &security_parameters,
            &key_block,
        )
        .expect("building finished message failed");

        let expected_encrypted_finished = hex::decode("16fefd0001000000000000004488e1762a41488a96b0cb44ebcaadecbb95a0cbc732800c1e50cbecaa09b55d0873e4278eb416b3bc6ee174ea95be16d0a64d73c237bd88e4470ad24f9d86c143fe57dcb4").expect("decode encrypted finished failed");
        let finished_iv = &expected_encrypted_finished
            [handshake::HANDSHAKE_TYPE_OFFSET..handshake::HANDSHAKE_TYPE_OFFSET + security_parameters.cipher_parameters.record_iv_length.0 as usize];

        let encrypted_finished = finished.encrypt(finished_iv, &security_parameters, &key_block).expect("encrypt failed");
        assert_eq!(encrypted_finished.len(), expected_encrypted_finished.len());
        assert_eq!(encrypted_finished, expected_encrypted_finished);

        // TODO same for server finished
    }

    // Borrowed test from rustls
    #[test]
    fn check_sha256() {
        let secret = b"\x9b\xbe\x43\x6b\xa9\x40\xf0\x17\xb1\x76\x52\x84\x9a\x71\xdb\x35";
        let seed = b"\xa0\xba\x9f\x93\x6c\xda\x31\x18\x27\xa6\xf7\x96\xff\xd5\x19\x8c";
        let label = b"test label";
        let expect = hex::decode("e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66").expect("decode bytes failed");
        let output = crypto::call_prf(expect.len(), secret, label, seed).expect("PRF failed");
        assert_eq!(expect.to_vec(), output.to_vec());
    }
}
