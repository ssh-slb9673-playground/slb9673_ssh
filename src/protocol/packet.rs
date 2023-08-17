use nom::AsBytes;

use super::error::SshError;
use crate::protocol::data::{Data, DataType};
use crate::protocol::session::Session;
use crate::utils::hexdump;

//   uint32    packet_length
//   byte      padding_length
//   byte[n1]  payload; n1 = packet_length - padding_length - 1 Initially, compression MUST be "none".
//   byte[n2]  random padding; n2 = padding_length
//   byte[m]   mac (Message Authentication Code - MAC); m = mac_length Initially, the MAC algorithm MUST be "none".
// mac = MAC(key, sequence_number || unencrypted_packet)
pub struct SshPacket<'a> {
    pub payload: Data,
    pub session: &'a mut Session,
}

impl<'a> SshPacket<'a> {
    pub fn unseal(&mut self) -> Result<Data, SshError> {
        let mut input = self.payload.clone().into_inner();
        let packet = self
            .session
            .client_method
            .enc_method
            .decrypt(&mut input, self.session.server_sequence_number)?;
        let mut packet = Data(packet);
        println!("plaintext");
        packet.hexdump();
        self.session.server_sequence_number += 1;

        let packet_length: u32 = packet.get();
        let padding_length: u8 = packet.get();
        let payload_length = packet_length - padding_length as u32 - 1;
        let mac_length = self.session.server_method.mac_method.size();
        let payload: Vec<u8> = packet.get_bytes(payload_length as usize);
        let padding: Vec<u8> = packet.get_bytes(padding_length as usize);
        let mac: Vec<u8> = packet.get_bytes(mac_length);

        let mut data = Data::new();
        data.put(&self.session.client_sequence_number)
            .put(&packet_length)
            .put(&padding_length)
            .put(&payload.as_bytes())
            .put(&padding.as_bytes());
        if self
            .session
            .server_method
            .mac_method
            .sign(&data.into_inner())
            != mac
        {
            return Err(SshError::ParseError);
        }
        Ok(Data(payload))
    }

    pub fn seal(&mut self) -> Vec<u8> {
        let payload = self.payload.clone().into_inner();

        let payload_length = (payload.len() + 1) as u32;
        let group_size = self.session.client_method.enc_method.group_size();
        let packet_length = if let None = self.session.client_kex {
            (payload_length + group_size - 1) / group_size * group_size + 4
        } else {
            (payload_length + group_size - 1) / group_size * group_size
        };
        let padding_length = (packet_length - payload_length) as u8;

        let mut data = Data::new();
        data.put(&packet_length)
            .put(&padding_length)
            .put(&payload.as_bytes())
            .put(&vec![0; padding_length as usize].as_bytes());
        let mut mac = Data::new();
        mac.put(&self.session.client_sequence_number).put(&data);
        let mac = self
            .session
            .client_method
            .mac_method
            .sign(&mac.into_inner());

        println!("plaintext");
        let packet = data.into_inner();
        hexdump(&packet);
        let mut encrypted_packet = packet.clone();
        self.session
            .client_method
            .enc_method
            .encrypt(&mut encrypted_packet, self.session.client_sequence_number);
        self.session.client_sequence_number += 1;

        mac.as_bytes().encode(&mut encrypted_packet);

        encrypted_packet
    }
}
