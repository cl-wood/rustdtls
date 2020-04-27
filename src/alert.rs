#[derive(Debug, Copy, Clone, PartialEq, Primitive)]
#[repr(u8)]
enum AlertLevel {
    Warning = 1,
    Fatal = 2,
}

#[derive(Debug, Copy, Clone, PartialEq, Primitive)]
#[repr(u8)]
enum AlertDescription {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    DecryptionFailedRESERVED = 21,
    RecordOverflow = 22,
    DecompressionFailure = 30,
    HandshakeFailure = 40,
    NoCertificateRESERVED = 41,
    BadCertificate = 42,
    UnsupportedCertificate = 43,
    CertificateRevoked = 44,
    CertificateExpired = 45,
    CertificateUnknown = 46,
    IllegalParameter = 47,
    UnknownCa = 48,
    AccessDenied = 49,
    DecodeError = 50,
    DecryptError = 51,
    ExportRestrictionRESERVED = 60,
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    UserCanceled = 90,
    NoRenegotiation = 100,
    UnsupportedExtension = 110,
}

#[allow(dead_code)]
struct Alert {
    level: AlertLevel,
    description: AlertDescription,
}
