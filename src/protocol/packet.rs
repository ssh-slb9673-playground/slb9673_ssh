use nom::AsBytes;

use super::error::{SshError, SshResult};
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
    pub fn unseal(&mut self) -> SshResult<Data> {
        let mut input = self.payload.clone().into_inner();
        let packet = self
            .session
            .client_method
            .enc_method
            .decrypt(&mut input, self.session.server_sequence_number)?;
        let mut packet = Data(packet);
        println!("plaintext");
        packet.hexdump();

        let packet_length: u32 = packet.get();
        let padding_length: u8 = packet.get();
        let payload_length = packet_length - padding_length as u32 - 1;
        let mac_length = self.session.server_method.mac_method.size();
        let payload: Vec<u8> = packet.get_bytes(payload_length as usize);
        let _padding: Vec<u8> = packet.get_bytes(padding_length as usize);
        let mac: Vec<u8> = packet.get_bytes(mac_length);

        if mac != self.calc_mac(packet_length, padding_length, payload.as_bytes()) {
            return Err(SshError::ParseError);
        }
        self.session.server_sequence_number += 1;

        Ok(Data(payload))
    }

    pub fn seal(&mut self) -> Vec<u8> {
        let payload = self.payload.clone().into_inner();

        let payload_length = (payload.len() + 1) as u32;
        let packet_length = self
            .session
            .client_method
            .enc_method
            .packet_length(payload_length);
        let padding_length = (packet_length - payload_length) as u8;

        let mut data = Data::new();
        data.put(&packet_length)
            .put(&padding_length)
            .put(&payload.as_bytes())
            .put(&vec![0; padding_length as usize].as_bytes());

        println!("plaintext");
        data.hexdump();

        self.session
            .client_method
            .enc_method
            .encrypt(&mut data, self.session.client_sequence_number);
        data.put(
            &self
                .calc_mac(packet_length, padding_length, payload.as_bytes())
                .as_bytes(),
        );

        self.session.client_sequence_number += 1;
        data.into_inner()
    }

    fn calc_mac(&self, packet_length: u32, padding_length: u8, payload: &[u8]) -> Vec<u8> {
        let mut data = Data::new();
        data.put(&self.session.client_sequence_number)
            .put(&packet_length)
            .put(&padding_length)
            .put(&payload.as_bytes())
            .put(&vec![0; padding_length as usize].as_bytes());
        self.session
            .server_method
            .mac_method
            .sign(&data.into_inner())
    }
}
