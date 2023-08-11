use nom::bytes::complete::take;
use nom::number::complete::be_u32;
use nom::IResult;

pub fn parse_string<'a>(input: &'a [u8]) -> IResult<&[u8], &'a [u8]> {
    let (input, length) = be_u32(input)?;
    let (input, payload) = take(length)(input)?;

    Ok((input, payload))
}

pub fn generate_string(input: &[u8]) -> Vec<u8> {
    let mut bytes = vec![];
    bytes.extend((input.len() as u32).to_be_bytes());
    bytes.extend(input);
    bytes
}

pub fn put_bytes(data: &mut Vec<u8>, input: &[u8]) {
    (*data).extend(input);
}

pub fn put_string(data: &mut Vec<u8>, input: &[u8]) {
    (*data).extend(&generate_string(input));
}

pub fn put_namelist(data: &mut Vec<u8>, namelist: &NameList) {
    (*data).extend(&generate_namelist(namelist));
}

pub fn to_mpint(input: &[u8]) -> Vec<u8> {
    let mut input = input.to_vec();
    if input[0] >= 0x80 {
        input.insert(0, 0x0);
    }
    input
}

pub type NameList = Vec<String>;

pub fn parse_namelist(input: &[u8]) -> IResult<&[u8], NameList> {
    let (input, algorithms) = parse_string(input)?;

    Ok((
        input,
        String::from_utf8(algorithms.to_vec())
            .unwrap()
            .split(',')
            .map(|s| s.into())
            .collect(),
    ))
}

pub fn generate_namelist(input: &NameList) -> Vec<u8> {
    generate_string(input.join(",").as_bytes())
}
