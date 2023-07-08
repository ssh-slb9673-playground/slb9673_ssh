use nom::bytes::complete::take;
use nom::number::complete::be_u32;
use nom::IResult;

pub fn parse_string(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let (input, length) = be_u32(input)?;
    let (input, payload) = take(length)(input)?;

    Ok((input, payload.to_vec()))
}
