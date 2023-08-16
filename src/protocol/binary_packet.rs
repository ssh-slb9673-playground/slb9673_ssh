use nom::bytes::complete::take;
use nom::IResult;

use crate::protocol::session::Session;
use crate::protocol::utils::DataType;

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

    pub fn decode<'a>(input: &'a [u8], session: &Session) -> IResult<&'a [u8], BinaryPacket> {
        let _input = input.clone();

        // session
        //     .client_method
        //     .enc_method
        //     .decrypt(&mut _input)
        //     .unwrap();
        // let packet = BinaryPacket::from_bytes(packet).to_bytes(&self);
        // self.client_sequence_number += 1;
        // encrypted_packet

        let (input, packet_length) = <u32>::decode(input)?;
        let (input, padding_length) = <u8>::decode(input)?;
        let payload_length = packet_length - padding_length as u32 - 1;
        let (input, payload) = take(payload_length)(input)?;
        let (input, padding) = take(padding_length)(input)?;
        let (_input, mac) = take(session.server_method.mac_method.size())(input)?;

        let mut tmp = vec![];
        session.client_sequence_number.encode(&mut tmp);
        _input.to_vec().encode(&mut tmp);
        if session.server_method.mac_method.generate(&tmp) != mac {
            panic!("match mac");
        }

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

    pub fn encode(&self, session: &mut Session) -> Vec<u8> {
        let mut packet = vec![];
        self.packet_length.encode(&mut packet);
        self.padding_length.encode(&mut packet);
        self.payload.encode(&mut packet);
        self.padding.encode(&mut packet);

        let mut mac = vec![];
        session.client_sequence_number.encode(&mut mac);
        packet.encode(&mut mac);
        mac = session.client_method.mac_method.generate(&mac);

        let mut encrypted_packet = packet.clone();
        let tag = session
            .client_method
            .enc_method
            .encrypt(&mut encrypted_packet);
        session.client_sequence_number += 1;

        mac.encode(&mut encrypted_packet);

        encrypted_packet
    }
}
