use crate::cipher::MACAlgorithm;
use crate::fields;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum DTLSError {
    #[error("Cipher not supported: {:x?}", _0)]
    CipherNotSupportedError(fields::Uint16),
    #[error("MACAlgorithm not supported: {:x?}", _0)]
    MACAlgorithmNotSupportedError(MACAlgorithm),

    #[error("Unspecified ring error")]
    UnspecifiedRingError,

    #[error("Cryptographic integrity error: {}", _0)]
    IntegrityError(&'static str),

    #[error("Some session fields were None")]
    SessionError,

    #[error("invalid length")]
    InvalidLengthError,
    #[error("Invalid handshake type.")]
    InvalidHandshakeTypeError,
    #[error("Invalid compression method.")]
    InvalidCompressionMethodError,
    #[error("{}", _0)]
    TryFromIntError(#[from] std::num::TryFromIntError),
    #[error("Invalid content type.")]
    InvalidContentTypeError,
    #[error("{}", _0)]
    SystemTimeError(#[from] std::time::SystemTimeError),
    #[error("{}", _0)]
    StdIoError(#[from] std::io::Error),
    #[error("{}", _0)]
    TryFromSliceError(#[from] std::array::TryFromSliceError),
    #[error("TryInto failed")]
    FromStringError, // TODO fix this
    #[error("{}", _0)]
    InvalidKeyIvLengthError(#[from] block_modes::InvalidKeyIvLength),
    #[error("{}", _0)]
    BlockModeError(#[from] block_modes::BlockModeError),
    //#[fail("{}", _0)]
    //InvalidKeyLengthError(#[from] crypto_mac::InvalidKeyLength),
    #[error("flight had the wrong number of messages")]
    FlightLengthError,

    #[error("datagram had the wrong number of records for application data")]
    RecordError,

    #[error("infallible error")]
    InfallibleError(#[from] std::convert::Infallible),
}
