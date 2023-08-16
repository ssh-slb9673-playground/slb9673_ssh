use core::fmt;
use nom::bytes::complete::take;
use nom::number::complete::{be_u32, be_u64, be_u8};
use nom::IResult;

/// Error type.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Character encoding-related errors.
    CharacterEncoding,
    /// Invalid label.
    Label,
    /// Invalid length.
    Length,
    /// Overflow errors.
    Overflow,
    /// Unexpected trailing data at end of message.
    TrailingData {
        /// Number of bytes of remaining data at end of message.
        remaining: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::CharacterEncoding => write!(f, "character encoding invalid"),
            Error::Label => write!(f, "label"),
            Error::Length => write!(f, "length invalid"),
            Error::Overflow => write!(f, "internal overflow error"),
            Error::TrailingData { remaining } => write!(
                f,
                "unexpected trailing data at end of message ({remaining} bytes)",
            ),
        }
    }
}

// [RFC4251 § 5](https://datatracker.ietf.org/doc/html/rfc4251#section-5)
pub trait DataType {
    fn size(&self) -> Result<usize, Error>;
    fn encode(&self, buf: &mut Vec<u8>);
    fn decode(input: &[u8]) -> IResult<&[u8], Self>
    where
        Self: Sized;
    fn to_bytes(&self) -> Vec<u8>;
}

impl DataType for bool {
    fn size(&self) -> Result<usize, Error> {
        Ok(1)
    }
    fn encode(&self, buf: &mut Vec<u8>) {
        if *self {
            buf.extend([1])
        } else {
            buf.extend([0])
        }
    }
    fn decode<'a>(input: &'a [u8]) -> IResult<&[u8], Self> {
        let (input, boolean) = be_u8(input)?;
        Ok((input, boolean != 0))
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        self.encode(&mut buf);
        buf
    }
}

// byte
impl DataType for u8 {
    fn size(&self) -> Result<usize, Error> {
        Ok(1)
    }
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend(self.to_be_bytes())
    }
    fn decode<'a>(input: &'a [u8]) -> IResult<&[u8], Self> {
        let (input, num) = be_u8(input)?;
        Ok((input, num))
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        self.encode(&mut buf);
        buf
    }
}

// uint32
impl DataType for u32 {
    fn size(&self) -> Result<usize, Error> {
        Ok(4)
    }
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend(&(*self as u32).to_be_bytes())
    }
    fn decode<'a>(input: &'a [u8]) -> IResult<&[u8], Self> {
        let (input, num) = be_u32(input)?;
        Ok((input, num))
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        self.encode(&mut buf);
        buf
    }
}

// uint32
impl DataType for usize {
    fn size(&self) -> Result<usize, Error> {
        Ok(4)
    }
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend(&(*self as u32).to_be_bytes())
    }
    fn decode<'a>(input: &'a [u8]) -> IResult<&[u8], Self> {
        let (input, num) = be_u32(input)?;
        Ok((input, num as usize))
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        self.encode(&mut buf);
        buf
    }
}

// uint64
impl DataType for u64 {
    fn size(&self) -> Result<usize, Error> {
        Ok(8)
    }
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend(&self.to_be_bytes())
    }
    fn decode<'a>(input: &'a [u8]) -> IResult<&[u8], Self> {
        let (input, num) = be_u64(input)?;
        Ok((input, num))
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        self.encode(&mut buf);
        buf
    }
}

// byte[n]
impl DataType for Vec<u8> {
    fn size(&self) -> Result<usize, Error> {
        Ok(self.len())
    }
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend(self)
    }
    fn decode<'a>(input: &'a [u8]) -> IResult<&[u8], Self> {
        todo!();
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        self.encode(&mut buf);
        buf
    }
}

// byte[n]
impl<const N: usize> DataType for [u8; N] {
    fn size(&self) -> Result<usize, Error> {
        Ok(N)
    }
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend(self)
    }
    fn decode<'a>(input: &'a [u8]) -> IResult<&[u8], Self> {
        let (input, result) = take(N as u8)(input)?;
        Ok((input, result.try_into().unwrap()))
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        self.encode(&mut buf);
        buf
    }
}

// string
pub struct ByteString(pub Vec<u8>);
impl DataType for ByteString {
    fn size(&self) -> Result<usize, Error> {
        Ok(self.0.len())
    }
    fn encode(&self, buf: &mut Vec<u8>) {
        self.0.len().encode(buf);
        self.0.encode(buf)
    }
    fn decode<'a>(input: &'a [u8]) -> IResult<&[u8], Self> {
        let (input, length) = be_u32(input)?;
        let (input, payload) = take(length)(input)?;
        Ok((input, ByteString(payload.to_vec())))
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        self.encode(&mut buf);
        buf
    }
}

// string
impl DataType for String {
    fn size(&self) -> Result<usize, Error> {
        Ok(self.len())
    }
    fn encode(&self, buf: &mut Vec<u8>) {
        self.len().encode(buf);
        self.as_bytes().to_vec().encode(buf);
    }
    fn decode<'a>(input: &'a [u8]) -> IResult<&[u8], Self> {
        let (input, length) = be_u32(input)?;
        let (input, payload) = take(length)(input)?;
        Ok((input, String::from_utf8(payload.to_vec()).unwrap()))
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        self.encode(&mut buf);
        buf
    }
}

// name-list
pub type NameList = Vec<String>;
impl DataType for NameList {
    fn size(&self) -> Result<usize, Error> {
        Ok(0)
    }
    fn encode(&self, buf: &mut Vec<u8>) {
        self.join(",").encode(buf)
    }
    fn decode<'a>(input: &'a [u8]) -> IResult<&[u8], Self> {
        let (input, payload) = String::decode(input)?;
        Ok((input, payload.split(',').map(|s| s.into()).collect()))
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        self.encode(&mut buf);
        buf
    }
}

// mpint
pub struct Mpint(pub Vec<u8>);
impl DataType for Mpint {
    fn size(&self) -> Result<usize, Error> {
        Ok(self.0.len())
    }
    fn encode(&self, buf: &mut Vec<u8>) {
        if self.0[0] >= 0x80 {
            (self.0.len() + 1).encode(buf);
            (0 as u8).encode(buf);
            self.0.encode(buf)
        } else {
            self.0.len().encode(buf);
            self.0.encode(buf)
        }
    }
    fn decode<'a>(input: &'a [u8]) -> IResult<&[u8], Self> {
        let (input, length) = be_u32(input)?;
        let (input, payload) = take(length)(input)?;
        Ok((input, Mpint(payload.to_vec())))
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        self.encode(&mut buf);
        buf
    }
}
