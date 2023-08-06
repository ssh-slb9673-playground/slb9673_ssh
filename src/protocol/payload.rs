use nom::number::complete::be_u8;
use nom::IResult;

use crate::protocol::key_exchange_init::KexAlgorithms;

enum Payload {
    KexInit(KexAlgorithms),
    None,
}
// pub enum MessageCode {
//     SSH_MSG_DISCONNECT,
//     SSH_MSG_IGNORE,
//     SSH_MSG_UNIMPLEMENTED,
//     SSH_MSG_DEBUG,
//     SSH_MSG_SERVICE_REQUEST,
//     SSH_MSG_SERVICE_ACCEPT,
//     SSH_MSG_EXT_INFO,
//     SSH_MSG_NEWCOMPRESS,
//     // Unassigned (Transport layer generic),
//     SSH_MSG_KEXINIT,
//     SSH_MSG_NEWKEYS,
//     // Unassigned (Algorithm negotiation),
//     EllipticCurveDiffieHellmanKeyExchangeInit,
//     EllipticCurveDiffieHellmanKeyExchangeReply,
//     // Reserved (key exchange method specific),
//     SSH_MSG_USERAUTH_REQUEST,
//     SSH_MSG_USERAUTH_FAILURE,
//     SSH_MSG_USERAUTH_SUCCESS,
//     SSH_MSG_USERAUTH_BANNER,
//     // Unassigned (User authentication generic),
//     SSH_MSG_USERAUTH_INFO_REQUEST,
//     SSH_MSG_USERAUTH_INFO_RESPONSE,
//     // Reserved (User authentication method specific),
//     SSH_MSG_GLOBAL_REQUEST,
//     SSH_MSG_REQUEST_SUCCESS,
//     SSH_MSG_REQUEST_FAILURE,
//     // Unassigned (Connection protocol generic),
//     SSH_MSG_CHANNEL_OPEN,
//     SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
//     SSH_MSG_CHANNEL_OPEN_FAILURE,
//     SSH_MSG_CHANNEL_WINDOW_ADJUST,
//     SSH_MSG_CHANNEL_DATA,
//     SSH_MSG_CHANNEL_EXTENDED_DATA,
//     SSH_MSG_CHANNEL_EOF,
//     SSH_MSG_CHANNEL_CLOSE,
//     SSH_MSG_CHANNEL_REQUEST,
//     SSH_MSG_CHANNEL_SUCCESS,
//     SSH_MSG_CHANNEL_FAILURE,
//     Unassigned,
//     Reserved,
//     NotFound,
// }

// pub fn parse_message_code(input: &[u8]) -> IResult<&[u8], MessageCode> {
//     let (input, message_code) = be_u8(input)?;
//     let message_code = match message_code {
//         20 => MessageCode::SSH_MSG_KEXINIT,
//         21 => MessageCode::SSH_MSG_NEWKEYS,
//         30 => MessageCode::EllipticCurveDiffieHellmanKeyExchangeInit,
//         31 => MessageCode::EllipticCurveDiffieHellmanKeyExchangeReply,
//         _ => MessageCode::NotFound,
//     };

//     Ok((input, message_code))
// }

impl Payload {
    pub fn parse_payload(input: &[u8]) -> IResult<&[u8], Payload> {
        let (input, message_id) = be_u8(input)?;
        match message_id {
            20 => {
                let (input, algorithms) = KexAlgorithms::parse_key_exchange_init(input)?;
                Ok((input, Payload::KexInit(algorithms)))
            }
            _ => Ok((input, Payload::None)),
        }
    }
}
