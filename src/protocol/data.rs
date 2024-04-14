use crate::utils::hexdump;
use nom::bytes::complete::take;
use nom::error::{Error, ErrorKind, ParseError};
use nom::number::complete::{be_u32, be_u64, be_u8};
use nom::{AsBytes, Err, IResult};

#[derive(Debug, Clone)]
pub struct Data(pub Vec<u8>);

impl Data {
    pub fn new() -> Data {
        Data(Vec::new())
    }

    pub fn put<T>(&mut self, v: &T) -> &mut Self
    where
        T: DataType,
    {
        v.encode(&mut self.0);
        self
    }

    pub fn get<T>(&mut self) -> T
    where
        T: DataType,
    {
        let (input, data) = match T::decode(&self.0) {
            Ok(t) => t,
            Err(e) => panic!("Error decoding {}", e),
        };
        let size = (input.as_ptr() as usize) - (self.0.as_ptr() as usize);
        self.0.drain(..size);
        data
    }

    pub fn expect<T>(&mut self, value: T)
    where
        T: DataType + std::cmp::PartialEq + std::fmt::Debug,
    {
        assert_eq!(self.get::<T>(), value);
    }

    pub fn get_bytes(&mut self, len: usize) -> Vec<u8> {
        let bytes = self.0.drain(..len).collect::<Vec<u8>>();
        bytes
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }

    pub fn hexdump(&self) {
        hexdump(&self.clone().into_inner());
    }
}

impl From<&[u8]> for Data {
    fn from(data: &[u8]) -> Self {
        Self(data.to_vec())
    }
}

// [RFC4251 § 5](https://datatracker.ietf.org/doc/html/rfc4251#section-5)
pub trait DataType {
    fn encode(&self, buf: &mut Vec<u8>);
    fn decode(input: &[u8]) -> IResult<&[u8], Self>
    where
        Self: Sized;
}

impl DataType for bool {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend([*self as u8])
    }
    fn decode(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, boolean) = be_u8(input)?;
        Ok((input, boolean != 0))
    }
}

// byte
impl DataType for u8 {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend(self.to_be_bytes())
    }
    fn decode(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, num) = be_u8(input)?;
        Ok((input, num))
    }
}

// uint32
impl DataType for u32 {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend(&self.to_be_bytes())
    }
    fn decode(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, num) = be_u32(input)?;
        Ok((input, num))
    }
}

// uint32
impl DataType for usize {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend(&(*self as u32).to_be_bytes())
    }
    fn decode(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, num) = be_u32(input)?;
        Ok((input, num as usize))
    }
}

// uint64
impl DataType for u64 {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend(&self.to_be_bytes())
    }
    fn decode(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, num) = be_u64(input)?;
        Ok((input, num))
    }
}

// byte[n]
impl DataType for &[u8] {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend(*self)
    }
    fn decode(_input: &[u8]) -> IResult<&[u8], Self> {
        todo!();
    }
}

// byte[n]
impl<const N: usize> DataType for [u8; N] {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend(self)
    }
    fn decode(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, result) = take(N as u8)(input)?;
        Ok((input, result.try_into().unwrap()))
    }
}

// string
#[derive(Debug)]
pub struct ByteString(pub Vec<u8>);
impl ByteString {
    pub fn from_str(value: &str) -> Self {
        ByteString(value.as_bytes().to_vec())
    }
}

impl DataType for ByteString {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.0.len().encode(buf);
        self.0.as_bytes().encode(buf)
    }
    fn decode(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, length) = be_u32(input)?;
        let (input, payload) = take(length)(input)?;
        Ok((input, ByteString(payload.to_vec())))
    }
}

// string
impl DataType for String {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.len().encode(buf);
        (*self).as_bytes().encode(buf);
    }
    fn decode(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, length) = be_u32(input)?;
        let (input, payload) = take(length)(input)?;
        Ok((input, String::from_utf8(payload.to_vec()).unwrap()))
    }
}

// name-list
pub type NameList = Vec<String>;
impl<T> DataType for Vec<T>
where
    T: std::fmt::Display + std::str::FromStr,
{
    fn encode(&self, buf: &mut Vec<u8>) {
        self.iter()
            .map(|v| v.to_string())
            .collect::<NameList>()
            .join(",")
            .encode(buf);
    }

    fn decode(input: &[u8]) -> IResult<&[u8], Self>
    where
        Self: Sized,
    {
        let (input, payload) = <ByteString>::decode(input)?;
        let result = String::from_utf8(payload.0)
            .unwrap()
            .split(',')
            .map(|s| s.to_string())
            .map(|v| T::from_str(&v))
            .collect::<Result<Vec<T>, _>>()
            .map_err(|_| Err::Error(Error::from_error_kind(input, ErrorKind::Eof)))?;
        Ok((input, result))
    }
}

// mpint
#[derive(Debug, Clone)]
pub struct Mpint(pub Vec<u8>);
impl DataType for Mpint {
    fn encode(&self, buf: &mut Vec<u8>) {
        if self.0[0] & 0x80 == 0 {
            self.0.len().encode(buf);
            self.0.as_bytes().encode(buf)
        } else {
            (self.0.len() + 1).encode(buf);
            0_u8.encode(buf);
            self.0.as_bytes().encode(buf)
        }
    }
    fn decode(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, length) = be_u32(input)?;
        let (input, payload) = take(length)(input)?;
        Ok((input, Mpint(payload.to_vec())))
    }
}

impl DataType for Data {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend(self.clone().into_inner());
    }
    fn decode(_input: &[u8]) -> IResult<&[u8], Self> {
        todo!();
    }
}
