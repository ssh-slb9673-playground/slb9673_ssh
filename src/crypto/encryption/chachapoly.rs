use super::Encryption;
use crate::protocol::{
    data::Data,
    error::{SshError, SshResult},
};
use ring::aead::chacha20_poly1305_openssh::{OpeningKey, SealingKey};

const BSIZE: usize = 64;

pub(crate) struct ChaCha20Poly1305 {
    client_key: SealingKey,
    server_key: OpeningKey,
}

impl ChaCha20Poly1305 {
    pub fn new(ck: &[u8], sk: &[u8]) -> Self {
        let mut sealing_key = [0_u8; BSIZE];
        let mut opening_key = [0_u8; BSIZE];
        sealing_key.copy_from_slice(&ck);
        opening_key.copy_from_slice(&sk);

        ChaCha20Poly1305 {
            client_key: SealingKey::new(&sealing_key),
            server_key: OpeningKey::new(&opening_key),
        }
    }
}

impl Encryption for ChaCha20Poly1305 {
    fn group_size(&self) -> u32 {
        64
    }
    fn packet_length(&mut self, payload_length: u32) -> u32 {
        let group_size = self.group_size();
        (payload_length + group_size - 1) / group_size * group_size
    }

    fn encrypt(&mut self, buf: &mut Data, sequence_number: u32) {
        let mut tag = [0_u8; 16];
        self.client_key
            .seal_in_place(sequence_number, &mut buf.0, &mut tag);
        buf.0.append(&mut tag.to_vec());
    }

    fn decrypt<'a>(
        &mut self,
        buf: &'a mut [u8],
        sequence_number: u32,
    ) -> SshResult<(&'a mut [u8], Vec<u8>, usize)> {
        let mut packet_len_slice: [u8; 4] = [0; 4];
        packet_len_slice.copy_from_slice(&buf[..4]);
        let packet_len_slice = self
            .server_key
            .decrypt_packet_length(sequence_number, packet_len_slice);
        let packet_len = u32::from_be_bytes(packet_len_slice);

        let (packet, buf) = buf.split_at_mut((packet_len + 4) as usize);
        let (tag, buf) = buf.split_at_mut(16 as usize);
        let tag: [u8; 16] = tag.try_into().unwrap();
        match self.server_key.open_in_place(sequence_number, packet, &tag) {
            Ok(result) => Ok((
                buf,
                [&packet_len_slice[..], result].concat(),
                (packet_len + 0x14) as usize,
            )),
            Err(_) => Err(SshError::RecvError("decrypt".to_string())),
        }
    }
}
