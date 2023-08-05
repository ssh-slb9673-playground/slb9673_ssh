use nom::bytes::complete::take;
use nom::number::complete::{be_u32, be_u8};
use nom::IResult;

//   uint32    packet_length
//   byte      padding_length
//   byte[n1]  payload; n1 = packet_length - padding_length - 1 Initially, compression MUST be "none".
//   byte[n2]  random padding; n2 = padding_length
//   byte[m]   mac (Message Authentication Code - MAC); m = mac_length Initially, the MAC algorithm MUST be "none".
pub struct BinaryPacket {
    packet_length: u32,
    padding_length: u8,
    payload: Vec<u8>,
    padding: Vec<u8>,
    mac: Vec<u8>,
}

impl BinaryPacket {
    pub fn parse_binary_packet(input: &[u8]) -> IResult<&[u8], BinaryPacket> {
        let mac_length: usize = 0;
        let (input, packet_length) = be_u32(input)?;
        let (input, padding_length) = be_u8(input)?;
        let (input, payload) = take(packet_length - padding_length as u32 - 1)(input)?;
        let (input, padding) = take(padding_length)(input)?;
        let (input, mac) = take(mac_length)(input)?;

        Ok((
            input,
            BinaryPacket {
                packet_length,
                padding_length,
                payload: payload.to_vec(),
                padding: padding.to_vec(),
                mac: mac.to_vec(),
            },
        ))
    }
}
