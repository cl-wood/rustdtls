use failure::Fail;
use std::convert::Infallible;

#[derive(Fail, Debug)]
pub enum DTLSError {
    #[fail(display = "invalid length")]
    InvalidLengthError,
    #[fail(display = "Invalid handshake type.")]
    InvalidHandshakeTypeError,
    #[fail(display = "Invalid compression method.")]
    InvalidCompressionMethodError,
    #[fail(display = "{}", _0)]
    TryFromIntError(#[cause] std::num::TryFromIntError),
    #[fail(display = "Invalid content type.")]
    InvalidContentTypeError,
    #[fail(display = "{}", _0)]
    SystemTimeError(#[cause] std::time::SystemTimeError),
    #[fail(display = "{}", _0)]
    StdIoError(#[cause] std::io::Error),
    #[fail(display = "{}", _0)]
    TryFromSliceError(#[cause] std::array::TryFromSliceError),
    #[fail(display = "TryInto failed")]
    FromStringError, // TODO fix this
    #[fail(display = "{}", _0)]
    InvalidKeyIvLengthError(#[cause] block_modes::InvalidKeyIvLength),
    #[fail(display = "{}", _0)]
    BlockModeError(#[cause] block_modes::BlockModeError),
    //#[fail(display = "{}", _0)]
    //InvalidKeyLengthError(#[cause] crypto_mac::InvalidKeyLength),
}

impl From<Infallible> for DTLSError {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}

impl From<std::num::TryFromIntError> for DTLSError {
    fn from(e: std::num::TryFromIntError) -> Self {
        DTLSError::TryFromIntError(e)
    }
}

impl From<std::time::SystemTimeError> for DTLSError {
    fn from(e: std::time::SystemTimeError) -> Self {
        DTLSError::SystemTimeError(e)
    }
}

impl From<std::io::Error> for DTLSError {
    fn from(e: std::io::Error) -> Self {
        DTLSError::StdIoError(e)
    }
}

impl From<std::array::TryFromSliceError> for DTLSError {
    fn from(e: std::array::TryFromSliceError) -> Self {
        DTLSError::TryFromSliceError(e)
    }
}

//std::convert::From<&str>` is not implemented for `errors::DTLSError`
impl From<&str> for DTLSError {
    fn from(_e: &str) -> Self {
        DTLSError::FromStringError //e.to_owned()
    }
}

impl From<block_modes::InvalidKeyIvLength> for DTLSError {
    fn from(e: block_modes::InvalidKeyIvLength) -> Self {
        DTLSError::InvalidKeyIvLengthError(e)
    }
}

impl From<block_modes::BlockModeError> for DTLSError {
    fn from(e: block_modes::BlockModeError) -> Self {
        DTLSError::BlockModeError(e)
    }
}

/*
impl From<crypto_mac::InvalidKeyLength> for DTLSError {
    fn from(e: crypto_mac::InvalidKeyLength) -> Self {
        DTLSError::InvalidKeyLengthError(e)
    }
}*/
