use nom::bytes::complete::take;
use nom::number::complete::{be_u32, be_u64, be_u8};
use nom::{AsBytes, IResult};

use crate::utils::hexdump;

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
        let (_, data) = T::decode(&self.0).unwrap();
        self.0.drain(..data.size());
        data
    }

    pub fn get_bytes(&mut self, len: usize) -> Vec<u8> {
        let bytes = self.0.drain(..len).into_iter().collect::<Vec<u8>>();
        bytes
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }

    pub fn hexdump(&self) {
        hexdump(&self.clone().into_inner());
    }
}

impl<'a> From<&'a [u8]> for Data {
    fn from(data: &'a [u8]) -> Self {
        Self(data.to_vec())
    }
}

// [RFC4251 § 5](https://datatracker.ietf.org/doc/html/rfc4251#section-5)
pub trait DataType {
    fn size(&self) -> usize;
    fn encode(&self, buf: &mut Vec<u8>);
    fn decode(input: &[u8]) -> IResult<&[u8], Self>
    where
        Self: Sized;
    fn to_bytes(&self) -> Vec<u8>;
}

impl DataType for bool {
    fn size(&self) -> usize {
        1
    }
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend([*self as u8])
    }
    fn decode<'a>(input: &'a [u8]) -> IResult<&[u8], Self> {
        let (input, boolean) = be_u8(input)?;
        Ok((input, boolean != 0))
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }
}

// byte
impl DataType for u8 {
    fn size(&self) -> usize {
        1
    }
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend(self.to_be_bytes())
    }
    fn decode<'a>(input: &'a [u8]) -> IResult<&[u8], Self> {
        let (input, num) = be_u8(input)?;
        Ok((input, num))
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }
}

// uint32
impl DataType for u32 {
    fn size(&self) -> usize {
        4
    }
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend(&(*self as u32).to_be_bytes())
    }
    fn decode<'a>(input: &'a [u8]) -> IResult<&[u8], Self> {
        let (input, num) = be_u32(input)?;
        Ok((input, num))
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }
}

// uint32
impl DataType for usize {
    fn size(&self) -> usize {
        4
    }
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend(&(*self as u32).to_be_bytes())
    }
    fn decode<'a>(input: &'a [u8]) -> IResult<&[u8], Self> {
        let (input, num) = be_u32(input)?;
        Ok((input, num as usize))
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }
}

// uint64
impl DataType for u64 {
    fn size(&self) -> usize {
        8
    }
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend(&self.to_be_bytes())
    }
    fn decode<'a>(input: &'a [u8]) -> IResult<&[u8], Self> {
        let (input, num) = be_u64(input)?;
        Ok((input, num))
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }
}

// byte[n]
impl DataType for &[u8] {
    fn size(&self) -> usize {
        self.len()
    }
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend(*self)
    }
    fn decode<'a>(_input: &'a [u8]) -> IResult<&[u8], Self> {
        todo!();
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }
}

// byte[n]
impl<const N: usize> DataType for [u8; N] {
    fn size(&self) -> usize {
        N
    }
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend(self)
    }
    fn decode<'a>(input: &'a [u8]) -> IResult<&[u8], Self> {
        let (input, result) = take(N as u8)(input)?;
        Ok((input, result.try_into().unwrap()))
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }
}

// string
pub struct ByteString(pub Vec<u8>);
impl ByteString {
    pub fn from_str(value: &str) -> Self {
        ByteString(value.as_bytes().to_vec())
    }
}

impl DataType for ByteString {
    fn size(&self) -> usize {
        self.0.len() + 4
    }
    fn encode(&self, buf: &mut Vec<u8>) {
        self.0.len().encode(buf);
        self.0.as_bytes().encode(buf)
    }
    fn decode<'a>(input: &'a [u8]) -> IResult<&[u8], Self> {
        let (input, length) = be_u32(input)?;
        let (input, payload) = take(length)(input)?;
        Ok((input, ByteString(payload.to_vec())))
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }
}

// string
impl DataType for String {
    fn size(&self) -> usize {
        self.len()
    }
    fn encode(&self, buf: &mut Vec<u8>) {
        self.len().encode(buf);
        (*self).as_bytes().encode(buf);
    }
    fn decode<'a>(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (input, length) = be_u32(input)?;
        let (input, payload) = take(length)(input)?;
        Ok((input, String::from_utf8(payload.to_vec()).unwrap()))
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }
}

// name-list
pub type NameList = Vec<String>;
impl DataType for NameList {
    fn size(&self) -> usize {
        self.join(",").len() + 4
    }
    fn encode(&self, buf: &mut Vec<u8>) {
        ByteString::from_str(&self.join(",")).encode(buf)
    }
    fn decode<'a>(input: &'a [u8]) -> IResult<&[u8], Self> {
        let (input, payload) = <ByteString>::decode(input)?;
        Ok((
            input,
            String::from_utf8(payload.0)
                .unwrap()
                .split(',')
                .map(|s| s.into())
                .collect(),
        ))
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }
}

// mpint
#[derive(Debug, Clone)]
pub struct Mpint(pub Vec<u8>);
impl DataType for Mpint {
    fn size(&self) -> usize {
        if self.0[0] & 0x80 == 0 {
            self.0.len() + 4
        } else {
            self.0.len() + 5
        }
    }
    fn encode(&self, buf: &mut Vec<u8>) {
        if self.0[0] & 0x80 == 0 {
            self.0.len().encode(buf);
            self.0.as_bytes().encode(buf)
        } else {
            (self.0.len() + 1).encode(buf);
            (0 as u8).encode(buf);
            self.0.as_bytes().encode(buf)
        }
    }
    fn decode<'a>(input: &'a [u8]) -> IResult<&[u8], Self> {
        let (input, length) = be_u32(input)?;
        let (input, payload) = take(length)(input)?;
        Ok((input, Mpint(payload.to_vec())))
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }
}

impl DataType for Data {
    fn size(&self) -> usize {
        self.0.len()
    }
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend(self.clone().into_inner());
    }
    fn decode<'a>(_input: &'a [u8]) -> IResult<&[u8], Self> {
        todo!();
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }
}
