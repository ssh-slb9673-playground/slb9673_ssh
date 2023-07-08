struct BinaryPacket {
    packet_length: u32,
    padding_length: u8,
    payload: Vec<u8>,
    random_padding: Vec<u8>,
    mac: Vec<u8>,
}

fn parse_ssh(input: &[u8]) -> IResult<&[u8], BinaryPacket> {
    let (input, packet_length) = be_u32(input)?;
    let (input, padding_length) = be_u8(input)?;
    let (input, payload) = take(packet_length)(input)?;
    let (input, padding) = take(padding_length)(input)?;
    let (input, mac) = take_until("eof")(input)?;

    Ok((
        input,
        BinaryPacket {
            packet_length,
            padding_length,
            payload: payload.to_vec(),
            random_padding: padding.to_vec(),
            mac: mac.to_vec(),
        },
    ))
}

fn parse(input: &[u8]) -> IResult<&[u8], ()> {
    let (input, message_code) = parse_message_code(input)?;
    match message_code {
        MessageCode::KeyExchangeInit => {
            let (input, wa) = parse_string(input)?;
        }
    };

    Ok((input, ()))
}
