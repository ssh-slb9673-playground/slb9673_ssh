#[derive(Debug)]
pub enum DisconnectCode {
    HostNotAllowedToConnect,
    ProtocolError,
    KeyExchangeFailed,
    Reserved,
    MacError,
    CompressionError,
    ServiceNotAvailable,
    ProtocolVersionNotSupported,
    HostKeyNotVerifiable,
    ConnectionLost,
    ByApplication,
    TooManyConnections,
    AuthCancelledByUser,
    NoMoreAuthMethodsAvailable,
    IllegalUserName,
}

impl std::error::Error for DisconnectCode {}

impl std::fmt::Display for DisconnectCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "error: ");
        match self {
            DisconnectCode::KeyExchangeFailed => write!(f, "key exchange failed"),
            _ => write!(f, "other error"),
        }
    }
}
