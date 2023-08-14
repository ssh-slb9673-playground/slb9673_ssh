use nom::bytes::complete::take;
use nom::number::complete::{be_u32, be_u8};
use nom::{Err, IResult};

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

    pub fn from_bytes<'a>(
        inencode: &'a [u8],
        session: &Session,
    ) -> IResult<&'a [u8], BinaryPacket> {
        let _inencode = inencode.clone();

        let (inencode, packet_length) = be_u32(inencode)?;
        let (inencode, padding_length) = be_u8(inencode)?;
        let payload_length = packet_length - padding_length as u32 - 1;
        let (inencode, payload) = take(payload_length)(inencode)?;
        let (inencode, padding) = take(padding_length)(inencode)?;
        let (_inencode, mac) = take(session.server_method.mac_method.size())(inencode)?;

        let mut tmp = vec![];
        session.client_sequence_number.encode(&mut tmp);
        _inencode.to_vec().encode(&mut tmp);
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

    pub fn to_bytes(&self, session: &Session) -> Vec<u8> {
        let mut packet = vec![];
        self.packet_length.encode(&mut packet);
        self.padding_length.encode(&mut packet);
        self.payload.encode(&mut packet);
        self.padding.encode(&mut packet);

        let mut mac = vec![];
        session.client_sequence_number.encode(&mut mac);
        packet.encode(&mut mac);
        session
            .client_method
            .mac_method
            .generate(&mac)
            .encode(&mut packet);

        packet
    }
}
