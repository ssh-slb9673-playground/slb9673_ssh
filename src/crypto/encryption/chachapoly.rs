//! OpenSSH variant of ChaCha20Poly1305: `chacha20-poly1305@openssh.com`
//!
//! Differences from ChaCha20Poly1305 as described in RFC8439:
//!
//! - Construction uses two separately keyed instances of ChaCha20: one for data, one for lengths
//! - The input of Poly1305 is not padded
//! - The lengths of ciphertext and AAD are not authenticated using Poly1305
//!
//! [PROTOCOL.chacha20poly1305]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD

// use crate::{Error, Nonce, Result, Tag};
use ring::aead::chacha20_poly1305_openssh::{OpeningKey, SealingKey};

use crate::protocol::error::SshError;

use super::Encryption;

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

    #[inline]
    fn encrypt(&mut self, buf: &mut Vec<u8>, sequence_number: u32) {
        let mut tag = [0_u8; 16];
        self.client_key
            .seal_in_place(sequence_number, buf, &mut tag);
        buf.append(&mut tag.to_vec());
    }

    #[inline]
    fn decrypt(
        &mut self,
        buf: &mut [u8],
        tag: &[u8],
        sequence_number: u32,
    ) -> Result<Vec<u8>, SshError> {
        let mut packet_len_slice = [0_u8; 4];
        let len = &buf[..4];
        packet_len_slice.copy_from_slice(len);
        let packet_len_slice = self
            .server_key
            .decrypt_packet_length(sequence_number, packet_len_slice);
        let packet_len = u32::from_be_bytes(packet_len_slice);
        let (buf, tag_) = buf.split_at_mut((packet_len + 4) as usize);
        let mut tag = [0_u8; 16];
        tag.copy_from_slice(tag_);
        match self.server_key.open_in_place(sequence_number, buf, &tag) {
            Ok(result) => Ok([&packet_len_slice[..], result].concat()),
            Err(_) => Err(SshError::ParseError),
        }
    }
}
