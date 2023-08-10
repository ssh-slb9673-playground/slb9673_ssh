use nom::bytes::complete::take;
use nom::number::complete::be_u32;
use nom::IResult;

pub fn parse_string(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let (input, length) = be_u32(input)?;
    let (input, payload) = take(length)(input)?;

    Ok((input, payload.to_vec()))
}

pub fn generate_string(input: &[u8]) -> Vec<u8> {
    let mut bytes = vec![];
    bytes.extend((input.len() as u32).to_be_bytes());
    bytes.extend(input);
    bytes
}

pub fn parse_mpint(input: &[u8]) {}

pub type NameList = Vec<String>;

pub fn parse_namelist(input: &[u8]) -> IResult<&[u8], NameList> {
    let (input, algorithms) = parse_string(input)?;

    Ok((
        input,
        String::from_utf8(algorithms)
            .unwrap()
            .split(',')
            .map(|s| s.into())
            .collect(),
    ))
}

pub fn generate_namelist(input: &NameList) -> Vec<u8> {
    generate_string(input.join(",").as_bytes())
}
