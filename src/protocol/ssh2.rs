pub mod MessageCode {
    // Transport layer protocol
    // 1 to 19    Transport layer generic (e.g., disconnect, ignore, debug, etc.)
    pub const SSH_MSG_DISCONNECT: u8 = 1;
    pub const SSH_MSG_IGNORE: u8 = 2;
    pub const SSH_MSG_UNIMPLEMENTED: u8 = 3;
    pub const SSH_MSG_DEBUG: u8 = 4;
    pub const SSH_MSG_SERVICE_REQUEST: u8 = 5;
    pub const SSH_MSG_SERVICE_ACCEPT: u8 = 6;
    pub const SSH_MSG_EXT_INFO: u8 = 7;
    // 20 to 29   Algorithm negotiation
    pub const SSH_MSG_KEXINIT: u8 = 20;
    pub const SSH_MSG_NEWKEYS: u8 = 21;
    // 30 to 49   Key exchange method specific (numbers can be reused for different authentication methods)
    /* dh-group-exchange */
    pub const SSH2_MSG_KEX_DH_GEX_REQUEST_OLD: u8 = 30;
    pub const SSH2_MSG_KEX_DH_GEX_GROUP: u8 = 31;
    pub const SSH2_MSG_KEX_DH_GEX_INIT: u8 = 32;
    pub const SSH2_MSG_KEX_DH_GEX_REPLY: u8 = 33;
    pub const SSH2_MSG_KEX_DH_GEX_REQUEST: u8 = 34;
    /* ecdh */
    pub const SSH2_MSG_KEX_ECDH_INIT: u8 = 30;
    pub const SSH2_MSG_KEX_ECDH_REPLY: u8 = 31;
    // User authentication protocol:
    // 50 to 59   User authentication generic
    pub const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
    pub const SSH_MSG_USERAUTH_FAILURE: u8 = 51;
    pub const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;
    pub const SSH_MSG_USERAUTH_BANNER: u8 = 53;
    // 60 to 79   User authentication method specific (numbers can be reused for different authentication methods)
    pub const SSH2_MSG_USERAUTH_PK_OK: u8 = 60;
    pub const SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ: u8 = 60;
    pub const SSH2_MSG_USERAUTH_INFO_REQUEST: u8 = 60;
    pub const SSH2_MSG_USERAUTH_INFO_RESPONSE: u8 = 61;
    // Connection protocol
    // 80 to 89   Connection protocol generic
    pub const SSH_MSG_GLOBAL_REQUEST: u8 = 80;
    pub const SSH_MSG_REQUEST_SUCCESS: u8 = 81;
    pub const SSH_MSG_REQUEST_FAILURE: u8 = 82;

    pub const SSH_MSG_CHANNEL_OPEN: u8 = 90;
    pub const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
    pub const SSH_MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
    pub const SSH_MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
    pub const SSH_MSG_CHANNEL_DATA: u8 = 94;
    pub const SSH_MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
    pub const SSH_MSG_CHANNEL_EOF: u8 = 96;
    pub const SSH_MSG_CHANNEL_CLOSE: u8 = 97;
    pub const SSH_MSG_CHANNEL_REQUEST: u8 = 98;
    pub const SSH_MSG_CHANNEL_SUCCESS: u8 = 99;
    pub const SSH_MSG_CHANNEL_FAILURE: u8 = 100;
    // 90 to 127  Channel related messages
    // Reserved for client protocols:
    // 128 to 191 Reserved
    // Local extensions:
    // 192 to 255 Local extensions
    /* misc */
    pub const SSH_OPEN_ADMINISTRATIVELY_PROHIBITED: u32 = 1;
    pub const SSH_OPEN_CONNECT_FAILED: u32 = 2;
    pub const SSH_OPEN_UNKNOWN_CHANNEL_TYPE: u32 = 3;
    pub const SSH_OPEN_RESOURCE_SHORTAGE: u32 = 4;

    pub const SSH2_EXTENDED_DATA_STDERR: u8 = 1;

    /* Certificate types for Openpub const SSH certificate keys extension */
    pub const SSH2_CERT_TYPE_USER: u8 = 1;
    pub const SSH2_CERT_TYPE_HOST: u8 = 1;

    // Disconnect Code
    pub const SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT: u8 = 1;
    pub const SSH_DISCONNECT_PROTOCOL_ERROR: u8 = 2;
    pub const SSH_DISCONNECT_KEY_EXCHANGE_FAILED: u8 = 3;
    pub const SSH_DISCONNECT_RESERVED: u8 = 4;
    pub const SSH_DISCONNECT_MAC_ERROR: u8 = 5;
    pub const SSH_DISCONNECT_COMPRESSION_ERROR: u8 = 6;
    pub const SSH_DISCONNECT_SERVICE_NOT_AVAILABLE: u8 = 7;
    pub const SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED: u8 = 8;
    pub const SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE: u8 = 9;
    pub const SSH_DISCONNECT_CONNECTION_LOST: u8 = 10;
    pub const SSH_DISCONNECT_BY_APPLICATION: u8 = 11;
    pub const SSH_DISCONNECT_TOO_MANY_CONNECTIONS: u8 = 12;
    pub const SSH_DISCONNECT_AUTH_CANCELLED_BY_USER: u8 = 13;
    pub const SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE: u8 = 14;
    pub const SSH_DISCONNECT_ILLEGAL_USER_NAME: u8 = 15;
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum ErrorCode {
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
            ErrorCode::SSH_ERR_SYSTEM_ERROR => "system error",
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
