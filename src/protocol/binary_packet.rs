use nom::bytes::complete::take;
use nom::number::complete::{be_u32, be_u8};
use nom::IResult;

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
    mac: Vec<u8>,
}

impl BinaryPacket {
    pub fn new(payload: Vec<u8>) -> Self {
        let payload_length = payload.len() as u32;
        let packet_length = (payload_length + 1) / 8 * 8;
        let padding_length = (packet_length - packet_length) as u8;
        BinaryPacket {
            packet_length,
            padding_length,
            payload,
            padding: vec![0; padding_length as usize],
            mac: vec![],
        }
    }

    pub fn parse_binary_packet(input: &[u8]) -> IResult<&[u8], BinaryPacket> {
        let mac_length: usize = 0;
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
                mac: mac.to_vec(),
            },
        ))
    }

    pub fn generate_binary_packet(&self) -> Vec<u8> {
        let mut packet = vec![];
        packet.extend(self.packet_length.to_be_bytes());
        packet.extend(self.padding_length.to_be_bytes());
        packet.extend(&self.payload);
        packet.extend(&self.padding);
        packet.extend(&self.mac);
        packet
    }
}
