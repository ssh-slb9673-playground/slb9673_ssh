use nom::{AsBytes, IResult};

use crate::protocol::data::{Data, DataType};
use crate::protocol::session::Session;
use crate::utils::hexdump;

use super::error::SshError;

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
    pub fn decode<'a>(input: &mut Data, session: &Session) -> Result<SshPacket, SshError> {
        // session
        //     .client_method
        //     .enc_method
        //     .decrypt(&mut _input)
        //     .unwrap();
        // let packet = BinaryPacket::from_bytes(packet).to_bytes(&self);
        // self.client_sequence_number += 1;
        // encrypted_packet

        let packet_length: u32 = input.get();
        let padding_length: u8 = input.get();
        println!("test");
        let payload_length = packet_length - padding_length as u32 - 1;
        println!("test");
        let payload: Vec<u8> = input.get_bytes(payload_length as usize);
        println!("test");
        let padding: Vec<u8> = input.get_bytes(padding_length as usize);
        let mac: Vec<u8> = input.get_bytes(session.server_method.mac_method.size());

        let mut data = Data::new();
        data.put(&session.client_sequence_number)
            .put(&packet_length)
            .put(&padding_length)
            .put(&payload.as_bytes())
            .put(&padding.as_bytes());
        if session.server_method.mac_method.sign(&data.into_inner()) != mac {
            return Err(SshError::ParseError);
        }

        Ok(SshPacket {
            payload: Data(payload),
        })
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
        let mut mac = Data::new();
        mac.put(&session.client_sequence_number).put(&data);
        let mac = session.client_method.mac_method.sign(&mac.into_inner());

        println!("pre enc");
        let packet = data.into_inner();
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

    pub fn into_inner(self) -> Data {
        self.payload
    }
}

impl<'a> From<Data> for SshPacket {
    fn from(data: Data) -> Self {
        Self { payload: data }
    }
}
