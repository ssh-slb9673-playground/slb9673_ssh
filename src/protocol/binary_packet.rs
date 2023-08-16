use nom::bytes::complete::take;
use nom::{AsBytes, IResult};

use crate::protocol::data::{Data, DataType};
use crate::protocol::session::Session;
use crate::utils::hexdump;

//   uint32    packet_length
//   byte      padding_length
//   byte[n1]  payload; n1 = packet_length - padding_length - 1 Initially, compression MUST be "none".
//   byte[n2]  random padding; n2 = padding_length
//   byte[m]   mac (Message Authentication Code - MAC); m = mac_length Initially, the MAC algorithm MUST be "none".
// mac = MAC(key, sequence_number || unencrypted_packet)
#[derive(Debug, Clone)]
pub struct SshPacket {
    payload: Data,
}

impl SshPacket {
    pub fn decode<'a>(input: &'a [u8], session: &Session) -> IResult<&'a [u8], SshPacket> {
        let _input = input.clone();

        // session
        //     .client_method
        //     .enc_method
        //     .decrypt(&mut _input)
        //     .unwrap();
        // let packet = BinaryPacket::from_bytes(packet).to_bytes(&self);
        // self.client_sequence_number += 1;
        // encrypted_packet

        let mut data: Data = input.into();
        let packet_length = data.get_u32();
        let padding_length = data.get_u8();
        let payload_length = packet_length - padding_length as u32 - 1;
        let (input, payload) = take(payload_length)(input)?;
        let (input, _) = take(padding_length)(input)?;
        let (_input, mac) = take(session.server_method.mac_method.size())(input)?;

        let mut data = Data::new();
        data.put(&session.client_sequence_number).put(&_input);
        if session
            .server_method
            .mac_method
            .generate(&data.into_inner())
            != mac
        {
            panic!("match mac");
        }

        let mut data = Data::new();
        data.put(&payload);

        Ok((payload, SshPacket { payload: data }))
    }

    pub fn encode(&self, session: &mut Session) -> Vec<u8> {
        let payload = self.payload.clone().into_inner();

        let payload_length = (payload.len() + 1) as u32;
        let group_size = session.client_method.enc_method.group_size();
        let mut packet_length = (payload_length + group_size - 1) / group_size * group_size;
        if let None = session.client_kex {
            packet_length += 4;
        }
        let padding_length = (packet_length - payload_length) as u8;
        let padding = vec![0; padding_length as usize];

        let mut data = Data::new();
        data.put(&packet_length)
            .put(&padding_length)
            .put(&payload.as_bytes())
            .put(&padding.as_bytes());
        let packet = data.into_inner();

        let mut mac = Data::new();
        mac.put(&session.client_sequence_number)
            .put(&packet.as_bytes());
        let mac = session.client_method.mac_method.generate(&mac.into_inner());

        println!("pre enc");
        hexdump(&packet);
        let mut encrypted_packet = packet.clone();
        session
            .client_method
            .enc_method
            .encrypt(&mut encrypted_packet, session.client_sequence_number);
        session.client_sequence_number += 1;

        mac.as_bytes().encode(&mut encrypted_packet);

        encrypted_packet
    }
}

impl<'a> From<Data> for SshPacket {
    fn from(data: Data) -> Self {
        Self { payload: data }
    }
}
