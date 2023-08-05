use nom::bytes::complete::take;
use nom::number::complete::be_u32;
use nom::IResult;

pub fn parse_string(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let (input, length) = be_u32(input)?;
    let (input, payload) = take(length)(input)?;

    Ok((input, payload.to_vec()))
}

pub fn generate_string(input: String) -> Vec<u8> {
    let mut bytes = vec![];
    bytes.extend((input.len() as u32).to_be_bytes());
    bytes.extend(input.as_bytes());
    bytes
}
