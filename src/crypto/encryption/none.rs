use super::EncryptionAdapter;
use crate::protocol::data::Data;

#[derive(Debug, Clone)]
pub struct NoneEncryption {}
impl EncryptionAdapter for NoneEncryption {
    // fn iv_size(&self) -> u32 {
    //     8
    // }
    // fn block_size(&self) -> u32 {
    //     8
    // }
    fn group_size(&self) -> u32 {
        8
    }
    fn packet_length(&mut self, payload_length: u32) -> u32 {
        let group_size = self.group_size();
        (payload_length + group_size - 1) / group_size * group_size + 4
    }

    fn encrypt(&mut self, _buffer: &mut Data, _sequence_number: u32) {}
    fn decrypt<'a>(
        &mut self,
        buffer: &'a mut [u8],
        _sequence_number: u32,
    ) -> anyhow::Result<(&'a mut [u8], Vec<u8>, usize)> {
        let mut packet_len_slice: [u8; 4] = [0; 4];
        packet_len_slice.copy_from_slice(&buffer[..4]);
        let packet_len = u32::from_be_bytes(packet_len_slice);
        let (packet, buffer) = buffer.split_at_mut((packet_len + 4) as usize);
        Ok((buffer, packet.to_vec(), (packet_len + 4) as usize))
    }
}
