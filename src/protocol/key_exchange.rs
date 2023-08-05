use crate::protocol::utils::parse_string;
use nom::{bytes::complete::take, number::complete::be_u32, IResult};

use super::utils::generate_string;

type NameList = Vec<String>;
#[derive(Debug)]
pub struct Algorithms {
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
}

impl Algorithms {
    pub fn parse_key_exchange(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, cookie) = take(16u8)(input)?;
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
        let (input, first_kex_packet_follows) = take(1u8)(input)?;
        let (input, _reserved) = be_u32(input)?;

        Ok((
            input,
            Algorithms {
                cookie: cookie.to_vec(),
                kex_algorithms: parse_name_list(kex_algorithms),
                server_host_key_algorithms: parse_name_list(server_host_key_algorithms),
                encryption_algorithms_client_to_server: parse_name_list(
                    encryption_algorithms_client_to_server,
                ),
                encryption_algorithms_server_to_client: parse_name_list(
                    encryption_algorithms_server_to_client,
                ),
                mac_algorithms_client_to_server: parse_name_list(mac_algorithms_client_to_server),
                mac_algorithms_server_to_client: parse_name_list(mac_algorithms_server_to_client),
                compression_algorithms_client_to_server: parse_name_list(
                    compression_algorithms_client_to_server,
                ),
                compression_algorithms_server_to_client: parse_name_list(
                    compression_algorithms_server_to_client,
                ),
                languages_client_to_server: parse_name_list(languages_client_to_server),
                languages_server_to_client: parse_name_list(languages_server_to_client),
                first_kex_packet_follows: first_kex_packet_follows[0] != 0,
            },
        ))
    }

    pub fn generate_key_exchange(&self) -> Vec<u8> {
        let mut packet: Vec<u8> = vec![];
        packet.extend(&self.cookie);
        packet.extend(generate_string(generate_name_list(&self.kex_algorithms)));
        packet.extend(generate_string(generate_name_list(
            &self.server_host_key_algorithms,
        )));
        packet.extend(generate_string(generate_name_list(
            &self.encryption_algorithms_client_to_server,
        )));
        packet.extend(generate_string(generate_name_list(
            &self.encryption_algorithms_server_to_client,
        )));
        packet.extend(generate_string(generate_name_list(
            &self.mac_algorithms_client_to_server,
        )));
        packet.extend(generate_string(generate_name_list(
            &self.mac_algorithms_server_to_client,
        )));
        packet.extend(generate_string(generate_name_list(
            &self.compression_algorithms_client_to_server,
        )));
        packet.extend(generate_string(generate_name_list(
            &self.compression_algorithms_server_to_client,
        )));
        packet.extend(generate_string(generate_name_list(
            &self.languages_client_to_server,
        )));
        packet.extend(generate_string(generate_name_list(
            &self.languages_server_to_client,
        )));
        packet.extend(generate_string(generate_name_list(
            &self.languages_server_to_client,
        )));
        packet.extend((self.first_kex_packet_follows as u8).to_be_bytes().to_vec());
        packet
    }
}

fn parse_name_list(algorithms: Vec<u8>) -> NameList {
    String::from_utf8(algorithms)
        .unwrap()
        .split(',')
        .map(|s| s.into())
        .collect()
}

fn generate_name_list(input: &NameList) -> String {
    let mut namelist = "".to_string();
    for iter in input.iter() {
        namelist += iter;
        namelist += ",";
    }
    namelist
}

#[test]
fn parse_test_key_exchange_packet() {
    // \x00\x00\x05\xdc\x04\x14
    let packet = b"\x11\x58\xa5\x0f\xa6\x66\x70\x27\x00\x75\x6b\xd9\x62\xe5\xdc\xb2\
\x00\x00\x01\x14\
curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,sntrup761x25519-sha512@openssh.com,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,ext-info-c\
\x00\x00\x01\xcf\
ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256\
\x00\x00\x00\x6c\
chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com\
\x00\x00\x00\x6c\
chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com\
\x00\x00\x00\xd5\
umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1\
\x00\x00\x00\xd5\
umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1\
\x00\x00\x00\x1a\
none,zlib@openssh.com,zlib\
\x00\x00\x00\x1a\
none,zlib@openssh.com,zlib\
\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    // \x00\x00\x00\x00\x00\x00\x00\x00
    let parsed = Algorithms::parse_key_exchange(packet);
    println!("{:?}", parsed);
}
