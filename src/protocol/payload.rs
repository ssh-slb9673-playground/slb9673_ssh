use nom::number::complete::be_u8;
use nom::IResult;

use crate::protocol::key_exchange::parse_key_exchange_packet;

use super::key_exchange::Algorithms;

enum Payload {
    kex_init(Algorithms),
    None,
}

impl Payload {
    pub fn parse_payload(input: &[u8]) -> IResult<&[u8], Payload> {
        let (input, message_id) = be_u8(input)?;
        match message_id {
            20 => {
                let algorithms = parse_key_exchange_packet(input)?.1;
                Ok((input, Payload::kex_init(algorithms)))
            }
            _ => Ok((input, Payload::None)),
        }
    }
}
