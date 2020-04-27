use crate::fields;

pub type CipherName = fields::Uint16;

#[allow(dead_code)]
pub const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: CipherName = fields::Uint16(0xc00a);
pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: CipherName = fields::Uint16(0xc014);
#[allow(dead_code)]
pub const TLS_DHE_RSA_WITH_AES_256_CBC_SHA: CipherName = fields::Uint16(0x0039);
#[allow(dead_code)]
pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: CipherName = fields::Uint16(0xc009);
#[allow(dead_code)]
pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: CipherName = fields::Uint16(0xc013);
#[allow(dead_code)]
pub const TLS_DHE_RSA_WITH_AES_128_CBC_SHA: CipherName = fields::Uint16(0x0033);
#[allow(dead_code)]
pub const TLS_RSA_WITH_AES_256_CBC_SHA: CipherName = fields::Uint16(0x0035);
#[allow(dead_code)]
pub const TLS_RSA_WITH_AES_128_CBC_SHA: CipherName = fields::Uint16(0x002f);
#[allow(dead_code)]
pub const TLS_ECDHE_RSA_AES_128_GCM_SHA256: CipherName = fields::Uint16(0xc02f);
#[allow(dead_code)]
pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: CipherName = fields::Uint16(0xc030);
pub const TLS_EMPTY_RENEGOTIATION_INFO_SCSV: CipherName = fields::Uint16(0x00ff);

#[derive(Clone, Copy)]
pub enum PRFAlgorithm {
    TlsPrfSha256,
}

#[derive(Clone, Copy)]
pub enum BulkCipherAlgorithm {
    #[allow(dead_code)]
    Null,
    #[allow(dead_code)]
    Rc4,
    #[allow(dead_code)]
    TripleDes,
    Aes,
}

#[derive(Clone, Copy)]
pub enum CipherType {
    Block,
    #[allow(dead_code)]
    Aead,
}
#[derive(Clone, Copy)]
pub enum MACAlgorithm {
    #[allow(dead_code)]
    Null,
    #[allow(dead_code)]
    HmacMd5,
    HmacSha1,
    #[allow(dead_code)]
    HmacSha256,
    #[allow(dead_code)]
    HmacSha384,
    #[allow(dead_code)]
    HmacSha512,
}

#[derive(Clone, Copy)]
pub struct CipherParameters {
    pub prf_algorithm: PRFAlgorithm,
    pub bulk_cipher_algorithm: BulkCipherAlgorithm,
    pub cipher_type: CipherType,
    pub enc_key_length: fields::Uint8,
    pub block_length: fields::Uint8,
    pub fixed_iv_length: fields::Uint8,
    pub record_iv_length: fields::Uint8,
    pub mac_algorithm: MACAlgorithm,
    pub mac_length: fields::Uint8,
    pub mac_key_length: fields::Uint8,
}

pub fn parameters(cipher: CipherName) -> CipherParameters {
    match cipher {
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA => CipherParameters {
            prf_algorithm: PRFAlgorithm::TlsPrfSha256,
            bulk_cipher_algorithm: BulkCipherAlgorithm::Aes,
            cipher_type: CipherType::Block,
            enc_key_length: fields::Uint8(32),
            block_length: fields::Uint8(16),
            fixed_iv_length: fields::Uint8(16), // IVs same for block ciphers
            record_iv_length: fields::Uint8(16),
            mac_algorithm: MACAlgorithm::HmacSha1,
            mac_length: fields::Uint8(20),
            mac_key_length: fields::Uint8(20),
        },

        // TODO should be unsupported cipher error
        _ => CipherParameters {
            prf_algorithm: PRFAlgorithm::TlsPrfSha256,
            bulk_cipher_algorithm: BulkCipherAlgorithm::Aes,
            cipher_type: CipherType::Block,
            enc_key_length: fields::Uint8(32),
            block_length: fields::Uint8(16),
            fixed_iv_length: fields::Uint8(16),
            record_iv_length: fields::Uint8(16),
            mac_algorithm: MACAlgorithm::HmacSha1,
            mac_length: fields::Uint8(20),
            mac_key_length: fields::Uint8(20),
        },
    }
}
