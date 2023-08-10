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
