use nom::bytes::complete::take;
use nom::number::complete::{be_u32, be_u8};
use nom::IResult;

use super::session::Session;
use super::utils::{parse_string, put_bytes};

//   uint32    packet_length
//   byte      padding_length
//   byte[n1]  payload; n1 = packet_length - padding_length - 1 Initially, compression MUST be "none".
//   byte[n2]  random padding; n2 = padding_length
//   byte[m]   mac (Message Authentication Code - MAC); m = mac_length Initially, the MAC algorithm MUST be "none".
// mac = MAC(key, sequence_number || unencrypted_packet)

#[derive(Debug)]
pub struct BinaryPacket {
    packet_length: u32,
    padding_length: u8,
    payload: Vec<u8>,
    padding: Vec<u8>,
}

impl BinaryPacket {
    pub fn new(payload: &[u8]) -> Self {
        let payload_length = (payload.len() + 1) as u32;
        let packet_length = (payload_length + 7) / 8 * 8 + 4;
        let padding_length = (packet_length - payload_length) as u8;
        BinaryPacket {
            packet_length,
            padding_length,
            payload: payload.to_vec(),
            padding: vec![0; padding_length as usize],
        }
    }

    pub fn from_bytes<'a>(input: &'a [u8], session: &Session) -> IResult<&'a [u8], BinaryPacket> {
        let mac_length: usize = 0;
        let (input, packet) = parse_string(input)?;
        let (input, packet_length) = be_u32(input)?;
        let (input, padding_length) = be_u8(input)?;
        let payload_length = packet_length - padding_length as u32 - 1;
        let (input, payload) = take(payload_length)(input)?;
        let (input, padding) = take(padding_length)(input)?;
        let (input, mac) = take(mac_length)(input)?;

        Ok((
            payload,
            BinaryPacket {
                packet_length,
                padding_length,
                payload: payload.to_vec(),
                padding: padding.to_vec(),
            },
        ))
    }

    pub fn to_bytes(&self, session: &Session) -> Vec<u8> {
        let mut packet = vec![];
        put_bytes(&mut packet, &self.packet_length.to_be_bytes());
        put_bytes(&mut packet, &self.padding_length.to_be_bytes());
        put_bytes(&mut packet, &self.payload);
        put_bytes(&mut packet, &self.padding);
        let mut tmp = vec![];
        put_bytes(&mut tmp, &session.client_sequence_number.to_be_bytes());
        put_bytes(&mut tmp, &packet);
        let mac = session.client_method.mac_method.generate(&tmp);
        put_bytes(&mut packet, &mac);
        packet
    }
}
