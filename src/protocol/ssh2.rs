#[derive(Debug)]
pub enum MessageCode {
    // Transport layer protocol
    // 1 to 19    Transport layer generic (e.g., disconnect, ignore, debug, etc.)
    SSH_MSG_DISCONNECT,
    SSH_MSG_IGNORE,
    SSH_MSG_UNIMPLEMENTED,
    SSH_MSG_DEBUG,
    SSH_MSG_SERVICE_REQUEST,
    SSH_MSG_SERVICE_ACCEPT,
    SSH_MSG_EXT_INFO,
    // 20 to 29   Algorithm negotiation
    SSH_MSG_KEXINIT,
    SSH_MSG_NEWKEYS,
    // 30 to 49   Key exchange method specific (numbers can be reused for different authentication methods)
    /* dh-group-exchange */
    SSH2_MSG_KEX_DH_GEX_REQUEST_OLD,
    SSH2_MSG_KEX_DH_GEX_GROUP,
    SSH2_MSG_KEX_DH_GEX_INIT,
    SSH2_MSG_KEX_DH_GEX_REPLY,
    SSH2_MSG_KEX_DH_GEX_REQUEST,
    /* ecdh */
    SSH2_MSG_KEX_ECDH_INIT,
    SSH2_MSG_KEX_ECDH_REPLY,
    // User authentication protocol:
    // 50 to 59   User authentication generic
    SSH_MSG_USERAUTH_REQUEST,
    SSH_MSG_USERAUTH_FAILURE,
    SSH_MSG_USERAUTH_SUCCESS,
    SSH_MSG_USERAUTH_BANNER,

    // 60 to 79   User authentication method specific (numbers can be reused for different authentication methods)
    SSH_MSG_GLOBAL_REQUEST,
    SSH_MSG_REQUEST_SUCCESS,
    SSH_MSG_REQUEST_FAILURE,

    SSH2_MSG_USERAUTH_PK_OK,
    SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ,
    SSH2_MSG_USERAUTH_INFO_REQUEST,
    SSH2_MSG_USERAUTH_INFO_RESPONSE,
    // Connection protocol
    // 80 to 89   Connection protocol generic
    SSH_MSG_CHANNEL_OPEN,
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
    SSH_MSG_CHANNEL_OPEN_FAILURE,
    SSH_MSG_CHANNEL_WINDOW_ADJUST,
    SSH_MSG_CHANNEL_DATA,
    SSH_MSG_CHANNEL_EXTENDED_DATA,
    SSH_MSG_CHANNEL_EOF,
    SSH_MSG_CHANNEL_CLOSE,
    SSH_MSG_CHANNEL_REQUEST,
    SSH_MSG_CHANNEL_SUCCESS,
    SSH_MSG_CHANNEL_FAILURE,
    // 90 to 127  Channel related messages
    // Reserved for client protocols:

    // 128 to 191 Reserved

    // Local extensions:

    // 192 to 255 Local extensions

    /* misc */
    SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED,
    SSH2_OPEN_CONNECT_FAILED,
    SSH2_OPEN_UNKNOWN_CHANNEL_TYPE,
    SSH2_OPEN_RESOURCE_SHORTAGE,

    SSH2_EXTENDED_DATA_STDERR,

    /* Certificate types for OpenSSH certificate keys extension */
    SSH2_CERT_TYPE_USER,
    SSH2_CERT_TYPE_HOST,
}

impl MessageCode {
    fn to_u8(&self) -> u8 {
        match *self {
            MessageCode::SSH_MSG_DISCONNECT => 1,
            MessageCode::SSH_MSG_IGNORE => 2,
            MessageCode::SSH_MSG_UNIMPLEMENTED => 3,
            MessageCode::SSH_MSG_DEBUG => 4,
            MessageCode::SSH_MSG_SERVICE_REQUEST => 5,
            MessageCode::SSH_MSG_SERVICE_ACCEPT => 6,
            MessageCode::SSH_MSG_EXT_INFO => 7,

            MessageCode::SSH_MSG_KEXINIT => 20,
            MessageCode::SSH_MSG_NEWKEYS => 21,

            MessageCode::SSH2_MSG_KEX_DH_GEX_REQUEST_OLD => 30,
            MessageCode::SSH2_MSG_KEX_DH_GEX_GROUP => 31,
            MessageCode::SSH2_MSG_KEX_DH_GEX_INIT => 32,
            MessageCode::SSH2_MSG_KEX_DH_GEX_REPLY => 33,
            MessageCode::SSH2_MSG_KEX_DH_GEX_REQUEST => 34,

            MessageCode::SSH2_MSG_KEX_ECDH_INIT => 30,
            MessageCode::SSH2_MSG_KEX_ECDH_REPLY => 31,

            MessageCode::SSH_MSG_USERAUTH_REQUEST => 50,
            MessageCode::SSH_MSG_USERAUTH_FAILURE => 51,
            MessageCode::SSH_MSG_USERAUTH_SUCCESS => 52,
            MessageCode::SSH_MSG_USERAUTH_BANNER => 53,

            MessageCode::SSH2_MSG_USERAUTH_PK_OK => 60,
            MessageCode::SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ => 60,
            MessageCode::SSH2_MSG_USERAUTH_INFO_REQUEST => 60,
            MessageCode::SSH2_MSG_USERAUTH_INFO_RESPONSE => 61,

            MessageCode::SSH_MSG_GLOBAL_REQUEST => 80,
            MessageCode::SSH_MSG_REQUEST_SUCCESS => 81,
            MessageCode::SSH_MSG_REQUEST_FAILURE => 82,

            MessageCode::SSH_MSG_CHANNEL_OPEN => 90,
            MessageCode::SSH_MSG_CHANNEL_OPEN_CONFIRMATION => 91,
            MessageCode::SSH_MSG_CHANNEL_OPEN_FAILURE => 92,
            MessageCode::SSH_MSG_CHANNEL_WINDOW_ADJUST => 93,
            MessageCode::SSH_MSG_CHANNEL_DATA => 94,
            MessageCode::SSH_MSG_CHANNEL_EXTENDED_DATA => 95,
            MessageCode::SSH_MSG_CHANNEL_EOF => 96,
            MessageCode::SSH_MSG_CHANNEL_CLOSE => 97,
            MessageCode::SSH_MSG_CHANNEL_REQUEST => 98,
            MessageCode::SSH_MSG_CHANNEL_SUCCESS => 99,
            MessageCode::SSH_MSG_CHANNEL_FAILURE => 100,
            _ => 0,
        }
    }

    pub fn from_u8(message_code: u8) -> Self {
        match message_code {
            20 => MessageCode::SSH_MSG_KEXINIT,
            21 => MessageCode::SSH_MSG_NEWKEYS,
            30 => MessageCode::SSH2_MSG_KEX_ECDH_INIT,
            31 => MessageCode::SSH2_MSG_KEX_ECDH_REPLY,
        }
    }
}

// pub fn parse_message_code(input: &[u8]) -> IResult<&[u8], MessageCode> {
//     let (input, message_code) = be_u8(input)?;

//     Ok((input, message_code))
// }

/* disconnect reason code */
#[derive(Debug)]
pub enum DisconnectCode {
    SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT,
    SSH2_DISCONNECT_PROTOCOL_ERROR,
    SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
    SSH2_DISCONNECT_HOST_AUTHENTICATION_FAILED,
    SSH2_DISCONNECT_RESERVED,
    SSH2_DISCONNECT_MAC_ERROR,
    SSH2_DISCONNECT_COMPRESSION_ERROR,
    SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE,
    SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED,
    SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE,
    SSH2_DISCONNECT_CONNECTION_LOST,
    SSH2_DISCONNECT_BY_APPLICATION,
    SSH2_DISCONNECT_TOO_MANY_CONNECTIONS,
    SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER,
    SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE,
    SSH2_DISCONNECT_ILLEGAL_USER_NAME,
}

impl std::error::Error for DisconnectCode {}

impl std::fmt::Display for DisconnectCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "error: ")?;
        match self {
            _ => write!(f, "error"),
        }
    }
}

enum ErrorCode {
    SSH_ERR_SUCCESS,
    SSH_ERR_INTERNAL_ERROR,
    SSH_ERR_ALLOC_FAIL,
    SSH_ERR_MESSAGE_INCOMPLETE,
    SSH_ERR_INVALID_FORMAT,
    SSH_ERR_BIGNUM_IS_NEGATIVE,
    SSH_ERR_STRING_TOO_LARGE,
    SSH_ERR_BIGNUM_TOO_LARGE,
    SSH_ERR_ECPOINT_TOO_LARGE,
    SSH_ERR_NO_BUFFER_SPACE,
    SSH_ERR_INVALID_ARGUMENT,
    SSH_ERR_KEY_BITS_MISMATCH,
    SSH_ERR_EC_CURVE_INVALID,
    SSH_ERR_KEY_TYPE_MISMATCH,
    SSH_ERR_KEY_TYPE_UNKNOWN,
    SSH_ERR_EC_CURVE_MISMATCH,
    SSH_ERR_EXPECTED_CERT,
    SSH_ERR_KEY_LACKS_CERTBLOB,
    SSH_ERR_KEY_CERT_UNKNOWN_TYPE,
    SSH_ERR_KEY_CERT_INVALID_SIGN_KEY,
    SSH_ERR_KEY_INVALID_EC_VALUE,
    SSH_ERR_SIGNATURE_INVALID,
    SSH_ERR_LIBCRYPTO_ERROR,
    SSH_ERR_UNEXPECTED_TRAILING_DATA,
    SSH_ERR_SYSTEM_ERROR,
    SSH_ERR_KEY_CERT_INVALID,
    SSH_ERR_AGENT_COMMUNICATION,
    SSH_ERR_AGENT_FAILURE,
    SSH_ERR_DH_GEX_OUT_OF_RANGE,
    SSH_ERR_DISCONNECTED,
    SSH_ERR_MAC_INVALID,
    SSH_ERR_NO_CIPHER_ALG_MATCH,
    SSH_ERR_NO_MAC_ALG_MATCH,
    SSH_ERR_NO_COMPRESS_ALG_MATCH,
    SSH_ERR_NO_KEX_ALG_MATCH,
    SSH_ERR_NO_HOSTKEY_ALG_MATCH,
    SSH_ERR_NO_HOSTKEY_LOADED,
    SSH_ERR_PROTOCOL_MISMATCH,
    SSH_ERR_NO_PROTOCOL_VERSION,
    SSH_ERR_NEED_REKEY,
    SSH_ERR_PASSPHRASE_TOO_SHORT,
    SSH_ERR_FILE_CHANGED,
    SSH_ERR_KEY_UNKNOWN_CIPHER,
    SSH_ERR_KEY_WRONG_PASSPHRASE,
    SSH_ERR_KEY_BAD_PERMISSIONS,
    SSH_ERR_KEY_CERT_MISMATCH,
    SSH_ERR_KEY_NOT_FOUND,
    SSH_ERR_AGENT_NOT_PRESENT,
    SSH_ERR_AGENT_NO_IDENTITIES,
    SSH_ERR_BUFFER_READ_ONLY,
    SSH_ERR_KRL_BAD_MAGIC,
    SSH_ERR_KEY_REVOKED,
    SSH_ERR_CONN_CLOSED,
    SSH_ERR_CONN_TIMEOUT,
    SSH_ERR_CONN_CORRUPT,
    SSH_ERR_PROTOCOL_ERROR,
    SSH_ERR_KEY_LENGTH,
    SSH_ERR_NUMBER_TOO_LARGE,
    SSH_ERR_SIGN_ALG_UNSUPPORTED,
    SSH_ERR_FEATURE_UNSUPPORTED,
    SSH_ERR_DEVICE_NOT_FOUND,
}

impl ErrorCode {
    pub fn to_int(&self) -> isize {
        match *self {
            ErrorCode::SSH_ERR_SUCCESS => 0,
            ErrorCode::SSH_ERR_INTERNAL_ERROR => -1,
            ErrorCode::SSH_ERR_ALLOC_FAIL => -2,
            ErrorCode::SSH_ERR_MESSAGE_INCOMPLETE => -3,
            ErrorCode::SSH_ERR_INVALID_FORMAT => -4,
            ErrorCode::SSH_ERR_BIGNUM_IS_NEGATIVE => -5,
            ErrorCode::SSH_ERR_STRING_TOO_LARGE => -6,
            ErrorCode::SSH_ERR_BIGNUM_TOO_LARGE => -7,
            ErrorCode::SSH_ERR_ECPOINT_TOO_LARGE => -8,
            ErrorCode::SSH_ERR_NO_BUFFER_SPACE => -9,
            ErrorCode::SSH_ERR_INVALID_ARGUMENT => -10,
            ErrorCode::SSH_ERR_KEY_BITS_MISMATCH => -11,
            ErrorCode::SSH_ERR_EC_CURVE_INVALID => -12,
            ErrorCode::SSH_ERR_KEY_TYPE_MISMATCH => -13,
            ErrorCode::SSH_ERR_KEY_TYPE_UNKNOWN => -14, /* XXX UNSUPPORTED? */
            ErrorCode::SSH_ERR_EC_CURVE_MISMATCH => -15,
            ErrorCode::SSH_ERR_EXPECTED_CERT => -16,
            ErrorCode::SSH_ERR_KEY_LACKS_CERTBLOB => -17,
            ErrorCode::SSH_ERR_KEY_CERT_UNKNOWN_TYPE => -18,
            ErrorCode::SSH_ERR_KEY_CERT_INVALID_SIGN_KEY => -19,
            ErrorCode::SSH_ERR_KEY_INVALID_EC_VALUE => -20,
            ErrorCode::SSH_ERR_SIGNATURE_INVALID => -21,
            ErrorCode::SSH_ERR_LIBCRYPTO_ERROR => -22,
            ErrorCode::SSH_ERR_UNEXPECTED_TRAILING_DATA => -23,
            ErrorCode::SSH_ERR_SYSTEM_ERROR => -24,
            ErrorCode::SSH_ERR_KEY_CERT_INVALID => -25,
            ErrorCode::SSH_ERR_AGENT_COMMUNICATION => -26,
            ErrorCode::SSH_ERR_AGENT_FAILURE => -27,
            ErrorCode::SSH_ERR_DH_GEX_OUT_OF_RANGE => -28,
            ErrorCode::SSH_ERR_DISCONNECTED => -29,
            ErrorCode::SSH_ERR_MAC_INVALID => -30,
            ErrorCode::SSH_ERR_NO_CIPHER_ALG_MATCH => -31,
            ErrorCode::SSH_ERR_NO_MAC_ALG_MATCH => -32,
            ErrorCode::SSH_ERR_NO_COMPRESS_ALG_MATCH => -33,
            ErrorCode::SSH_ERR_NO_KEX_ALG_MATCH => -34,
            ErrorCode::SSH_ERR_NO_HOSTKEY_ALG_MATCH => -35,
            ErrorCode::SSH_ERR_NO_HOSTKEY_LOADED => -36,
            ErrorCode::SSH_ERR_PROTOCOL_MISMATCH => -37,
            ErrorCode::SSH_ERR_NO_PROTOCOL_VERSION => -38,
            ErrorCode::SSH_ERR_NEED_REKEY => -39,
            ErrorCode::SSH_ERR_PASSPHRASE_TOO_SHORT => -40,
            ErrorCode::SSH_ERR_FILE_CHANGED => -41,
            ErrorCode::SSH_ERR_KEY_UNKNOWN_CIPHER => -42,
            ErrorCode::SSH_ERR_KEY_WRONG_PASSPHRASE => -43,
            ErrorCode::SSH_ERR_KEY_BAD_PERMISSIONS => -44,
            ErrorCode::SSH_ERR_KEY_CERT_MISMATCH => -45,
            ErrorCode::SSH_ERR_KEY_NOT_FOUND => -46,
            ErrorCode::SSH_ERR_AGENT_NOT_PRESENT => -47,
            ErrorCode::SSH_ERR_AGENT_NO_IDENTITIES => -48,
            ErrorCode::SSH_ERR_BUFFER_READ_ONLY => -49,
            ErrorCode::SSH_ERR_KRL_BAD_MAGIC => -50,
            ErrorCode::SSH_ERR_KEY_REVOKED => -51,
            ErrorCode::SSH_ERR_CONN_CLOSED => -52,
            ErrorCode::SSH_ERR_CONN_TIMEOUT => -53,
            ErrorCode::SSH_ERR_CONN_CORRUPT => -54,
            ErrorCode::SSH_ERR_PROTOCOL_ERROR => -55,
            ErrorCode::SSH_ERR_KEY_LENGTH => -56,
            ErrorCode::SSH_ERR_NUMBER_TOO_LARGE => -57,
            ErrorCode::SSH_ERR_SIGN_ALG_UNSUPPORTED => -58,
            ErrorCode::SSH_ERR_FEATURE_UNSUPPORTED => -59,
            ErrorCode::SSH_ERR_DEVICE_NOT_FOUND => -60,
        }
    }
    pub fn to_str(&self) -> &str {
        match *self {
            ErrorCode::SSH_ERR_SUCCESS => "success",
            ErrorCode::SSH_ERR_INTERNAL_ERROR => "unexpected internal error",
            ErrorCode::SSH_ERR_ALLOC_FAIL => "memory allocation failed",
            ErrorCode::SSH_ERR_MESSAGE_INCOMPLETE => "incomplete message",
            ErrorCode::SSH_ERR_INVALID_FORMAT => "invalid format",
            ErrorCode::SSH_ERR_BIGNUM_IS_NEGATIVE => "bignum is negative",
            ErrorCode::SSH_ERR_STRING_TOO_LARGE => "string is too large",
            ErrorCode::SSH_ERR_BIGNUM_TOO_LARGE => "bignum is too large",
            ErrorCode::SSH_ERR_ECPOINT_TOO_LARGE => "elliptic curve point is too large",
            ErrorCode::SSH_ERR_NO_BUFFER_SPACE => "insufficient buffer space",
            ErrorCode::SSH_ERR_INVALID_ARGUMENT => "invalid argument",
            ErrorCode::SSH_ERR_KEY_BITS_MISMATCH => "key bits do not match",
            ErrorCode::SSH_ERR_EC_CURVE_INVALID => "invalid elliptic curve",
            ErrorCode::SSH_ERR_KEY_TYPE_MISMATCH => "key type does not match",
            ErrorCode::SSH_ERR_KEY_TYPE_UNKNOWN => "unknown or unsupported key type",
            ErrorCode::SSH_ERR_EC_CURVE_MISMATCH => "elliptic curve does not match",
            ErrorCode::SSH_ERR_EXPECTED_CERT => "plain key provided where certificate required",
            ErrorCode::SSH_ERR_KEY_LACKS_CERTBLOB => "key lacks certificate data",
            ErrorCode::SSH_ERR_KEY_CERT_UNKNOWN_TYPE => "unknown/unsupported certificate type",
            ErrorCode::SSH_ERR_KEY_CERT_INVALID_SIGN_KEY => "invalid certificate signing key",
            ErrorCode::SSH_ERR_KEY_INVALID_EC_VALUE => "invalid elliptic curve value",
            ErrorCode::SSH_ERR_SIGNATURE_INVALID => "incorrect signature",
            ErrorCode::SSH_ERR_LIBCRYPTO_ERROR => "error in libcrypto", /* XXX fetch and return */
            ErrorCode::SSH_ERR_UNEXPECTED_TRAILING_DATA => "unexpected bytes remain after decoding",
            ErrorCode::SSH_ERR_SYSTEM_ERROR => strerror(errno),
            ErrorCode::SSH_ERR_KEY_CERT_INVALID => "invalid certificate",
            ErrorCode::SSH_ERR_AGENT_COMMUNICATION => "communication with agent failed",
            ErrorCode::SSH_ERR_AGENT_FAILURE => "agent refused operation",
            ErrorCode::SSH_ERR_DH_GEX_OUT_OF_RANGE => "DH GEX group out of range",
            ErrorCode::SSH_ERR_DISCONNECTED => "disconnected",
            ErrorCode::SSH_ERR_MAC_INVALID => "message authentication code incorrect",
            ErrorCode::SSH_ERR_NO_CIPHER_ALG_MATCH => "no matching cipher found",
            ErrorCode::SSH_ERR_NO_MAC_ALG_MATCH => "no matching MAC found",
            ErrorCode::SSH_ERR_NO_COMPRESS_ALG_MATCH => "no matching compression method found",
            ErrorCode::SSH_ERR_NO_KEX_ALG_MATCH => "no matching key exchange method found",
            ErrorCode::SSH_ERR_NO_HOSTKEY_ALG_MATCH => "no matching host key type found",
            ErrorCode::SSH_ERR_PROTOCOL_MISMATCH => "protocol version mismatch",
            ErrorCode::SSH_ERR_NO_PROTOCOL_VERSION => "could not read protocol version",
            ErrorCode::SSH_ERR_NO_HOSTKEY_LOADED => "could not load host key",
            ErrorCode::SSH_ERR_NEED_REKEY => "rekeying not supported by peer",
            ErrorCode::SSH_ERR_PASSPHRASE_TOO_SHORT => {
                "passphrase is too short (minimum five characters)"
            }
            ErrorCode::SSH_ERR_FILE_CHANGED => "file changed while reading",
            ErrorCode::SSH_ERR_KEY_UNKNOWN_CIPHER => "key encrypted using unsupported cipher",
            ErrorCode::SSH_ERR_KEY_WRONG_PASSPHRASE => {
                "incorrect passphrase supplied to decrypt private key"
            }
            ErrorCode::SSH_ERR_KEY_BAD_PERMISSIONS => "bad permissions",
            ErrorCode::SSH_ERR_KEY_CERT_MISMATCH => "certificate does not match key",
            ErrorCode::SSH_ERR_KEY_NOT_FOUND => "key not found",
            ErrorCode::SSH_ERR_AGENT_NOT_PRESENT => "agent not present",
            ErrorCode::SSH_ERR_AGENT_NO_IDENTITIES => "agent contains no identities",
            ErrorCode::SSH_ERR_BUFFER_READ_ONLY => "internal error: buffer is read-only",
            ErrorCode::SSH_ERR_KRL_BAD_MAGIC => "KRL file has invalid magic number",
            ErrorCode::SSH_ERR_KEY_REVOKED => "Key is revoked",
            ErrorCode::SSH_ERR_CONN_CLOSED => "Connection closed",
            ErrorCode::SSH_ERR_CONN_TIMEOUT => "Connection timed out",
            ErrorCode::SSH_ERR_CONN_CORRUPT => "Connection corrupted",
            ErrorCode::SSH_ERR_PROTOCOL_ERROR => "Protocol error",
            ErrorCode::SSH_ERR_KEY_LENGTH => "Invalid key length",
            ErrorCode::SSH_ERR_NUMBER_TOO_LARGE => "number is too large",
            ErrorCode::SSH_ERR_SIGN_ALG_UNSUPPORTED => "signature algorithm not supported",
            ErrorCode::SSH_ERR_FEATURE_UNSUPPORTED => "requested feature not supported",
            ErrorCode::SSH_ERR_DEVICE_NOT_FOUND => "device not found",
            _ => "unknown error",
        }
    }
}
