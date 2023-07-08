use nom::bytes::complete::{take, take_until};
use nom::number::complete::{be_u32, be_u8};
use nom::IResult;

fn parse_string(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let (input, length) = be_u32(input)?;
    let (input, payload) = take(length)(input)?;

    Ok((input, payload.to_vec()))
}
