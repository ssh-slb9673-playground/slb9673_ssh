use nom::bytes::complete::take;
use nom::number::complete::{be_u32, be_u64, be_u8};
use nom::IResult;

pub trait DataType {
    fn size(&self) -> Option<usize>;
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self>
    where
        Self: Sized;
    fn to_bytes(&self) -> Vec<u8>;
    fn put(&self, data: &mut Vec<u8>);
}

pub type Byte = Vec<u8>;
impl DataType for Byte {
    fn size(&self) -> Option<usize> {
        Some(self.len())
    }
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self>
    where
        Self: Sized,
    {
        todo!()
    }
    fn to_bytes(&self) -> Vec<u8> {
        self.clone()
    }
    fn put(&self, data: &mut Vec<u8>) {
        data.extend(self.to_bytes());
    }
}

pub type Boolean = bool;
impl DataType for Boolean {
    fn size(&self) -> Option<usize> {
        Some(1)
    }
    fn from_bytes<'a>(input: &'a [u8]) -> IResult<&[u8], Self> {
        let (input, boolean) = be_u8(input)?;
        Ok((input, boolean != 0))
    }
    fn to_bytes(&self) -> Vec<u8> {
        if *self {
            vec![1]
        } else {
            vec![0]
        }
    }
    fn put(&self, data: &mut Vec<u8>) {
        data.extend(self.to_bytes());
    }
}

impl DataType for u8 {
    fn size(&self) -> Option<usize> {
        Some(1)
    }
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self>
    where
        Self: Sized,
    {
        let (input, num) = be_u8(input)?;
        Ok((input, num))
    }
    fn to_bytes(&self) -> Vec<u8> {
        (*self).to_be_bytes().to_vec()
    }
    fn put(&self, data: &mut Vec<u8>) {
        data.extend(self.to_bytes());
    }
}

// uint32
// Represents a 32-bit unsigned integer. Stored as four bytes in the order of decreasing significance (network byte order). For example: the value 699921578 (0x29b7f4aa) is stored as 29 b7 f4 aa.
impl DataType for u32 {
    fn size(&self) -> Option<usize> {
        Some(4)
    }
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self>
    where
        Self: Sized,
    {
        let (input, num) = be_u32(input)?;
        Ok((input, num))
    }
    fn to_bytes(&self) -> Vec<u8> {
        (*self).to_be_bytes().to_vec()
    }
    fn put(&self, data: &mut Vec<u8>) {
        data.extend(self.to_bytes());
    }
}

// uint64
// Represents a 64-bit unsigned integer. Stored as eight bytes in the order of decreasing significance (network byte order).
impl DataType for u64 {
    fn size(&self) -> Option<usize> {
        Some(8)
    }
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self>
    where
        Self: Sized,
    {
        let (input, num) = be_u64(input)?;
        Ok((input, num))
    }
    fn to_bytes(&self) -> Vec<u8> {
        (*self).to_be_bytes().to_vec()
    }
    fn put(&self, data: &mut Vec<u8>) {
        data.extend(self.to_bytes());
    }
}

// string
// Arbitrary length binary string. Strings are allowed to contain arbitrary binary data, including null characters and 8-bit characters. They are stored as a uint32 containing its length (number of bytes that follow) and zero (= empty string) or more bytes that are the value of the string. Terminating null characters are not used.
// Strings are also used to store text. In that case, US-ASCII is used for internal names, and ISO-10646 UTF-8 for text that might be displayed to the user. The terminating null character SHOULD NOT normally be stored in the string. For example: the US-ASCII string "testing" is represented as 00 00 00 07 t e s t i n g. The UTF-8 mapping does not alter the encoding of US-ASCII characters.
pub struct ByteString(pub Vec<u8>);
impl DataType for ByteString {
    fn size(&self) -> Option<usize> {
        None
    }
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self>
    where
        Self: Sized,
    {
        let (input, length) = be_u32(input)?;
        let (input, payload) = take(length)(input)?;

        Ok((input, ByteString(payload.to_vec())))
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend((self.0.len() as u32).to_be_bytes());
        bytes.extend(&self.0);
        bytes
    }
    fn put(&self, data: &mut Vec<u8>) {
        data.extend(self.to_bytes());
    }
}

// mpint
// Represents multiple precision integers in two's complement format, stored as a string, 8 bits per byte, MSB first. Negative numbers have the value 1 as the most significant bit of the first byte of the data partition. If the most significant bit would be set for a positive number, the number MUST be preceded by a zero byte. Unnecessary leading bytes with the value 0 or 255 MUST NOT be included. The value zero MUST be stored as a string with zero bytes of data.
// 多精度整数を2の補数形式で表し、1バイトあたり8ビット、MSBファーストの文字列として格納されます。負の数は、データパーティションの最初のバイトの最上位ビットとして値1を持ちます。最上位ビットが正の数に設定される場合は、数値の前にゼロバイトを付ける必要があります。値0または255の不要な先行バイトを含めてはなりません（MUST NOT）。値0は、0バイトのデータを持つ文字列として格納する必要があります。
// By convention, a number that is used in modular computations in Z_n SHOULD be represented in the range 0 <= x < n.
// 慣例により、Z_nのモジュラー計算で使用される数値は、0 <= x <nの範囲で表す必要があります（SHOULD）。

// Examples:
//          value (hex)        representation (hex)
//          -----------        --------------------
//          0                  00 00 00 00
//          9a378f9b2e332a7    00 00 00 08 09 a3 78 f9 b2 e3 32 a7
//          80                 00 00 00 02 00 80
//          -1234              00 00 00 02 ed cc
//          -deadbeef          00 00 00 05 ff 21 52 41 11
// pub type Mpint = u64;
// impl DataType for Mpint {
//     fn size(&self) -> Option<usize> {
//         None
//     }
//     fn from_bytes(input: &[u8]) -> IResult<&[u8], Self>
//     where
//         Self: Sized,
//     {
//         let mut input = input.to_vec();
//         if input[0] >= 0x80 {
//             input.insert(0, 0x0);
//         }
//         input
//     }
//     fn to_bytes(&self) -> Vec<u8> {}
// }

// name-list
// A string containing a comma-separated list of names. A name-list is represented as a uint32 containing its length (number of bytes that follow) followed by a comma-separated list of zero or more names. A name MUST have a non-zero length, and it MUST NOT contain a comma (","). As this is a list of names, all of the elements contained are names and MUST be in US-ASCII. Context may impose additional restrictions on the names. For example, the names in a name-list may have to be a list of valid algorithm identifiers (see Section 6 below), or a list of [RFC3066] language tags. The order of the names in a name-list may or may not be significant. Again, this depends on the context in which the list is used. Terminating null characters MUST NOT be used, neither for the individual names, nor for the list as a whole.
// Examples:
//        value                      representation (hex)
//        -----                      --------------------
//        (), the empty name-list    00 00 00 00
//        ("zlib")                   00 00 00 04 7a 6c 69 62
//        ("zlib,none")              00 00 00 09 7a 6c 69 62 2c 6e 6f 6e 65
pub type NameList = Vec<String>;
impl DataType for NameList {
    fn size(&self) -> Option<usize> {
        None
    }
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self>
    where
        Self: Sized,
    {
        let (input, algorithms) = ByteString::from_bytes(input)?;
        Ok((
            input,
            String::from_utf8(algorithms.0)
                .unwrap()
                .split(',')
                .map(|s| s.into())
                .collect(),
        ))
    }
    fn to_bytes(&self) -> Vec<u8> {
        ByteString(self.join(",").into_bytes()).to_bytes()
    }
    fn put(&self, data: &mut Vec<u8>) {
        data.extend(self.to_bytes());
    }
}
