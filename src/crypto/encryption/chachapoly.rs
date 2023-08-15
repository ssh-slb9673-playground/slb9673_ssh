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
use chacha20::{ChaCha20Legacy, Key};
use cipher::{KeyInit, KeyIvInit, StreamCipher, StreamCipherSeek};
use poly1305::Poly1305;
use subtle::ConstantTimeEq;

const KEY_SIZE: usize = 32;
pub type Nonce = [u8; 12];
pub type Tag = [u8; 16];
use core::fmt;

use super::Encryption;

/// Result type with `ssh-cipher` crate's [`Error`] as the error type.
pub type Result<T> = core::result::Result<T, Error>;

/// Error type.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Cryptographic errors.
    Crypto,

    /// Invalid key size.
    KeySize,

    /// Invalid initialization vector / nonce size.
    IvSize,

    /// Invalid AEAD tag size.
    TagSize,

    /// Unsupported cipher.
    UnsupportedCipher,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Crypto => write!(f, "cryptographic error"),
            Error::KeySize => write!(f, "invalid key size"),
            Error::IvSize => write!(f, "invalid initialization vector size"),
            Error::TagSize => write!(f, "invalid AEAD tag size"),
            Error::UnsupportedCipher => write!(f, "unsupported cipher"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

pub(crate) struct ChaCha20Poly1305 {
    cipher: ChaCha20Legacy,
    mac: Poly1305,
}

impl ChaCha20Poly1305 {
    pub fn new(key: &[u8], nonce: &[u8]) -> Result<Self> {
        #[allow(clippy::arithmetic_side_effects)]
        if key.len() != KEY_SIZE * 2 {
            return Err(Error::KeySize);
        }

        // TODO(tarcieri): support for using both keys
        let (k_2, _k_1) = key.split_at(KEY_SIZE);
        let key = Key::from_slice(k_2);

        let nonce = if nonce.is_empty() {
            // For key encryption
            Nonce::default()
        } else {
            Nonce::try_from(nonce).map_err(|_| Error::IvSize)?
        };

        let mut cipher = ChaCha20Legacy::new(key, &nonce.into());
        let mut poly1305_key = poly1305::Key::default();
        cipher.apply_keystream(&mut poly1305_key);

        let mac = Poly1305::new(&poly1305_key);

        // Seek to block 1
        cipher.seek(64);

        Ok(Self { cipher, mac })
    }
}

impl Encryption for ChaCha20Poly1305 {
    #[inline]
    fn encrypt(&mut self, buffer: &mut [u8]) -> Option<Vec<u8>> {
        self.cipher.apply_keystream(buffer);
        let tag: Tag = self.mac.clone().compute_unpadded(buffer).into();
        Some(tag.to_vec())
    }

    #[inline]
    fn decrypt(&mut self, buffer: &mut [u8], tag: &[u8]) -> Result<()> {
        let expected_tag = self.mac.clone().compute_unpadded(buffer);

        if expected_tag.ct_eq(&tag).into() {
            self.cipher.apply_keystream(buffer);
            Ok(())
        } else {
            Err(Error::Crypto)
        }
    }
}

//const u_char one[8] = { 1, 0, 0, 0, 0, 0, 0, 0 }; /* NB little-endian */
// impl chacha20_poly1305 {
//     pub fn new(key: &[u8], nonce: &[u8]) -> Self {
//         let cipher = ChaCha20Poly1305::new(key.into());
//         println!("nonce: {}", hex(nonce));
//         println!("key: {}", hex(key));
//         chacha20_poly1305 {
//             cipher,
//             nonce: *GenericArray::from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]),
//         }
//     }
// }
// impl Encryption for chacha20_poly1305 {
//     fn encrypt(&mut self, plaintext: &[u8]) -> Option<Vec<u8>> {
//         self.cipher.encrypt(&self.nonce, plaintext).ok()
//     }
//     fn decrypt(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>> {
//         self.cipher.decrypt(&self.nonce, ciphertext).ok()
//     }
// }
