use crate::protocol::utils::parse_string;
use nom::IResult;
use std::string::FromUtf8Error;

type NameList = Vec<String>;
struct Algorithms {
    cookie: Vec<u8>,
    kex_algorithms: NameList,
    server_host_key_algorithms: NameList,
    encryption_algorithms_client_to_server: NameList,
    encryption_algorithms_server_to_client: NameList,
    mac_algorithms_client_to_server: NameList,
    mac_algorithms_server_to_client: NameList,
    compression_algorithms_client_to_server: NameList,
    compression_algorithms_server_to_client: NameList,
    languages_client_to_server: NameList,
    languages_server_to_client: NameList,
    first_kex_packet_follows: bool,
    reserved: u32,
}

fn name_list<'a>(algorithms: Vec<u8>) -> Result<Vec<String>, FromUtf8Error> {
    Ok(String::from_utf8(algorithms)?
        .split(',')
        .map(|s| s.into())
        .collect())
}

fn parse_key_exchange_packet(input: &[u8]) -> IResult<&[u8], Algorithms> {
    let (input, cookie) = parse_string(input)?;
    let (input, kex_algorithms) = parse_string(input)?;
    let (input, server_host_key_algorithms) = parse_string(input)?;
    let (input, encryption_algorithms_client_to_server) = parse_string(input)?;
    let (input, encryption_algorithms_server_to_client) = parse_string(input)?;
    let (input, mac_algorithms_client_to_server) = parse_string(input)?;
    let (input, mac_algorithms_server_to_client) = parse_string(input)?;
    let (input, compression_algorithms_client_to_server) = parse_string(input)?;
    let (input, compression_algorithms_server_to_client) = parse_string(input)?;
    let (input, languages_client_to_server) = parse_string(input)?;
    let (input, languages_server_to_client) = parse_string(input)?;

    let kex_algorithms = name_list(kex_algorithms).unwrap();
    let server_host_key_algorithms = name_list(server_host_key_algorithms).unwrap();
    let encryption_algorithms_client_to_server =
        name_list(encryption_algorithms_client_to_server).unwrap();
    let encryption_algorithms_server_to_client =
        name_list(encryption_algorithms_server_to_client).unwrap();
    let mac_algorithms_client_to_server = name_list(mac_algorithms_client_to_server).unwrap();
    let mac_algorithms_server_to_client = name_list(mac_algorithms_server_to_client).unwrap();
    let compression_algorithms_client_to_server =
        name_list(compression_algorithms_client_to_server).unwrap();
    let compression_algorithms_server_to_client =
        name_list(compression_algorithms_server_to_client).unwrap();
    let languages_client_to_server = name_list(languages_client_to_server).unwrap();
    let languages_server_to_client = name_list(languages_server_to_client).unwrap();

    Ok((
        input,
        Algorithms {
            cookie,
            kex_algorithms,
            server_host_key_algorithms,
            encryption_algorithms_client_to_server,
            encryption_algorithms_server_to_client,
            mac_algorithms_client_to_server,
            mac_algorithms_server_to_client,
            compression_algorithms_client_to_server,
            compression_algorithms_server_to_client,
            languages_client_to_server,
            languages_server_to_client,
            first_kex_packet_follows: true,
            reserved: 0,
        },
    ))
}

#[test]
fn parse_test_key_exchange_packet() {
    let packet = b"\x00\x00\x05\xdc\x04\x14\x11\x58\xa5\x0f\xa6\x66\x70\x27\x00\x75 \
\x6b\xd9\x62\xe5\xdc\xb2\x00\x00\x01\x14\x63\x75\x72\x76\x65\x32 \
\x35\x35\x31\x39\x2d\x73\x68\x61\x32\x35\x36\x2c\x63\x75\x72\x76 \
\x65\x32\x35\x35\x31\x39\x2d\x73\x68\x61\x32\x35\x36\x40\x6c\x69 \
\x62\x73\x73\x68\x2e\x6f\x72\x67\x2c\x65\x63\x64\x68\x2d\x73\x68 \
\x61\x32\x2d\x6e\x69\x73\x74\x70\x32\x35\x36\x2c\x65\x63\x64\x68 \
\x2d\x73\x68\x61\x32\x2d\x6e\x69\x73\x74\x70\x33\x38\x34\x2c\x65 \
\x63\x64\x68\x2d\x73\x68\x61\x32\x2d\x6e\x69\x73\x74\x70\x35\x32 \
\x31\x2c\x73\x6e\x74\x72\x75\x70\x37\x36\x31\x78\x32\x35\x35\x31 \
\x39\x2d\x73\x68\x61\x35\x31\x32\x40\x6f\x70\x65\x6e\x73\x73\x68 \
\x2e\x63\x6f\x6d\x2c\x64\x69\x66\x66\x69\x65\x2d\x68\x65\x6c\x6c \
\x6d\x61\x6e\x2d\x67\x72\x6f\x75\x70\x2d\x65\x78\x63\x68\x61\x6e \
\x67\x65\x2d\x73\x68\x61\x32\x35\x36\x2c\x64\x69\x66\x66\x69\x65 \
\x2d\x68\x65\x6c\x6c\x6d\x61\x6e\x2d\x67\x72\x6f\x75\x70\x31\x36 \
\x2d\x73\x68\x61\x35\x31\x32\x2c\x64\x69\x66\x66\x69\x65\x2d\x68 \
\x65\x6c\x6c\x6d\x61\x6e\x2d\x67\x72\x6f\x75\x70\x31\x38\x2d\x73 \
\x68\x61\x35\x31\x32\x2c\x64\x69\x66\x66\x69\x65\x2d\x68\x65\x6c \
\x6c\x6d\x61\x6e\x2d\x67\x72\x6f\x75\x70\x31\x34\x2d\x73\x68\x61 \
\x32\x35\x36\x2c\x65\x78\x74\x2d\x69\x6e\x66\x6f\x2d\x63\x00\x00 \
\x01\xcf\x73\x73\x68\x2d\x65\x64\x32\x35\x35\x31\x39\x2d\x63\x65 \
\x72\x74\x2d\x76\x30\x31\x40\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63 \
\x6f\x6d\x2c\x65\x63\x64\x73\x61\x2d\x73\x68\x61\x32\x2d\x6e\x69 \
\x73\x74\x70\x32\x35\x36\x2d\x63\x65\x72\x74\x2d\x76\x30\x31\x40 \
\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f\x6d\x2c\x65\x63\x64\x73 \
\x61\x2d\x73\x68\x61\x32\x2d\x6e\x69\x73\x74\x70\x33\x38\x34\x2d \
\x63\x65\x72\x74\x2d\x76\x30\x31\x40\x6f\x70\x65\x6e\x73\x73\x68 \
\x2e\x63\x6f\x6d\x2c\x65\x63\x64\x73\x61\x2d\x73\x68\x61\x32\x2d \
\x6e\x69\x73\x74\x70\x35\x32\x31\x2d\x63\x65\x72\x74\x2d\x76\x30 \
\x31\x40\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f\x6d\x2c\x73\x6b \
\x2d\x73\x73\x68\x2d\x65\x64\x32\x35\x35\x31\x39\x2d\x63\x65\x72 \
\x74\x2d\x76\x30\x31\x40\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f \
\x6d\x2c\x73\x6b\x2d\x65\x63\x64\x73\x61\x2d\x73\x68\x61\x32\x2d \
\x6e\x69\x73\x74\x70\x32\x35\x36\x2d\x63\x65\x72\x74\x2d\x76\x30 \
\x31\x40\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f\x6d\x2c\x72\x73 \
\x61\x2d\x73\x68\x61\x32\x2d\x35\x31\x32\x2d\x63\x65\x72\x74\x2d \
\x76\x30\x31\x40\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f\x6d\x2c \
\x72\x73\x61\x2d\x73\x68\x61\x32\x2d\x32\x35\x36\x2d\x63\x65\x72 \
\x74\x2d\x76\x30\x31\x40\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f \
\x6d\x2c\x73\x73\x68\x2d\x65\x64\x32\x35\x35\x31\x39\x2c\x65\x63 \
\x64\x73\x61\x2d\x73\x68\x61\x32\x2d\x6e\x69\x73\x74\x70\x32\x35 \
\x36\x2c\x65\x63\x64\x73\x61\x2d\x73\x68\x61\x32\x2d\x6e\x69\x73 \
\x74\x70\x33\x38\x34\x2c\x65\x63\x64\x73\x61\x2d\x73\x68\x61\x32 \
\x2d\x6e\x69\x73\x74\x70\x35\x32\x31\x2c\x73\x6b\x2d\x73\x73\x68 \
\x2d\x65\x64\x32\x35\x35\x31\x39\x40\x6f\x70\x65\x6e\x73\x73\x68 \
\x2e\x63\x6f\x6d\x2c\x73\x6b\x2d\x65\x63\x64\x73\x61\x2d\x73\x68 \
\x61\x32\x2d\x6e\x69\x73\x74\x70\x32\x35\x36\x40\x6f\x70\x65\x6e \
\x73\x73\x68\x2e\x63\x6f\x6d\x2c\x72\x73\x61\x2d\x73\x68\x61\x32 \
\x2d\x35\x31\x32\x2c\x72\x73\x61\x2d\x73\x68\x61\x32\x2d\x32\x35 \
\x36\x00\x00\x00\x6c\x63\x68\x61\x63\x68\x61\x32\x30\x2d\x70\x6f \
\x6c\x79\x31\x33\x30\x35\x40\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63 \
\x6f\x6d\x2c\x61\x65\x73\x31\x32\x38\x2d\x63\x74\x72\x2c\x61\x65 \
\x73\x31\x39\x32\x2d\x63\x74\x72\x2c\x61\x65\x73\x32\x35\x36\x2d \
\x63\x74\x72\x2c\x61\x65\x73\x31\x32\x38\x2d\x67\x63\x6d\x40\x6f \
\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f\x6d\x2c\x61\x65\x73\x32\x35 \
\x36\x2d\x67\x63\x6d\x40\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f \
\x6d\x00\x00\x00\x6c\x63\x68\x61\x63\x68\x61\x32\x30\x2d\x70\x6f \
\x6c\x79\x31\x33\x30\x35\x40\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63 \
\x6f\x6d\x2c\x61\x65\x73\x31\x32\x38\x2d\x63\x74\x72\x2c\x61\x65 \
\x73\x31\x39\x32\x2d\x63\x74\x72\x2c\x61\x65\x73\x32\x35\x36\x2d \
\x63\x74\x72\x2c\x61\x65\x73\x31\x32\x38\x2d\x67\x63\x6d\x40\x6f \
\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f\x6d\x2c\x61\x65\x73\x32\x35 \
\x36\x2d\x67\x63\x6d\x40\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f \
\x6d\x00\x00\x00\xd5\x75\x6d\x61\x63\x2d\x36\x34\x2d\x65\x74\x6d \
\x40\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f\x6d\x2c\x75\x6d\x61 \
\x63\x2d\x31\x32\x38\x2d\x65\x74\x6d\x40\x6f\x70\x65\x6e\x73\x73 \
\x68\x2e\x63\x6f\x6d\x2c\x68\x6d\x61\x63\x2d\x73\x68\x61\x32\x2d \
\x32\x35\x36\x2d\x65\x74\x6d\x40\x6f\x70\x65\x6e\x73\x73\x68\x2e \
\x63\x6f\x6d\x2c\x68\x6d\x61\x63\x2d\x73\x68\x61\x32\x2d\x35\x31 \
\x32\x2d\x65\x74\x6d\x40\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f \
\x6d\x2c\x68\x6d\x61\x63\x2d\x73\x68\x61\x31\x2d\x65\x74\x6d\x40 \
\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f\x6d\x2c\x75\x6d\x61\x63 \
\x2d\x36\x34\x40\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f\x6d\x2c \
\x75\x6d\x61\x63\x2d\x31\x32\x38\x40\x6f\x70\x65\x6e\x73\x73\x68 \
\x2e\x63\x6f\x6d\x2c\x68\x6d\x61\x63\x2d\x73\x68\x61\x32\x2d\x32 \
\x35\x36\x2c\x68\x6d\x61\x63\x2d\x73\x68\x61\x32\x2d\x35\x31\x32 \
\x2c\x68\x6d\x61\x63\x2d\x73\x68\x61\x31\x00\x00\x00\xd5\x75\x6d \
\x61\x63\x2d\x36\x34\x2d\x65\x74\x6d\x40\x6f\x70\x65\x6e\x73\x73 \
\x68\x2e\x63\x6f\x6d\x2c\x75\x6d\x61\x63\x2d\x31\x32\x38\x2d\x65 \
\x74\x6d\x40\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f\x6d\x2c\x68 \
\x6d\x61\x63\x2d\x73\x68\x61\x32\x2d\x32\x35\x36\x2d\x65\x74\x6d \
\x40\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f\x6d\x2c\x68\x6d\x61 \
\x63\x2d\x73\x68\x61\x32\x2d\x35\x31\x32\x2d\x65\x74\x6d\x40\x6f \
\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f\x6d\x2c\x68\x6d\x61\x63\x2d \
\x73\x68\x61\x31\x2d\x65\x74\x6d\x40\x6f\x70\x65\x6e\x73\x73\x68 \
\x2e\x63\x6f\x6d\x2c\x75\x6d\x61\x63\x2d\x36\x34\x40\x6f\x70\x65 \
\x6e\x73\x73\x68\x2e\x63\x6f\x6d\x2c\x75\x6d\x61\x63\x2d\x31\x32 \
\x38\x40\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f\x6d\x2c\x68\x6d \
\x61\x63\x2d\x73\x68\x61\x32\x2d\x32\x35\x36\x2c\x68\x6d\x61\x63 \
\x2d\x73\x68\x61\x32\x2d\x35\x31\x32\x2c\x68\x6d\x61\x63\x2d\x73 \
\x68\x61\x31\x00\x00\x00\x1a\x6e\x6f\x6e\x65\x2c\x7a\x6c\x69\x62 \
\x40\x6f\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f\x6d\x2c\x7a\x6c\x69 \
\x62\x00\x00\x00\x1a\x6e\x6f\x6e\x65\x2c\x7a\x6c\x69\x62\x40\x6f \
\x70\x65\x6e\x73\x73\x68\x2e\x63\x6f\x6d\x2c\x7a\x6c\x69\x62\x00 \
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
}
