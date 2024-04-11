use super::client::SshClient;
use super::data::{Data, DataType, NameList};
use super::ssh2::message_code;

#[derive(Debug, Clone)]
pub struct KexAlgorithms {
    pub cookie: [u8; 16],
    pub kex_algorithms: NameList,
    pub server_host_key_algorithms: NameList,
    pub encryption_algorithms_client_to_server: NameList,
    pub encryption_algorithms_server_to_client: NameList,
    pub mac_algorithms_client_to_server: NameList,
    pub mac_algorithms_server_to_client: NameList,
    pub compression_algorithms_client_to_server: NameList,
    pub compression_algorithms_server_to_client: NameList,
    pub languages_client_to_server: NameList,
    pub languages_server_to_client: NameList,
    pub first_kex_packet_follows: bool,
    pub reserved: u32,
}

impl SshClient {
    pub fn key_exchange_init(&mut self) -> anyhow::Result<()> {
        // recv key algorithms
        let mut payload = self.recv()?;
        payload.expect(message_code::SSH_MSG_KEXINIT);
        let server_kex_algorithms = payload.get();

        // send key algorithms
        self.send(
            Data::new()
                .put(&message_code::SSH_MSG_KEXINIT)
                .put(&self.kex),
        )?;

        self.session
            .set_kex_algorithms(&self.kex, &server_kex_algorithms);

        println!("server algorithms: {:?}", server_kex_algorithms);
        println!("client algorithms: {:?}", self.kex);

        Ok(())
    }
}

impl DataType for KexAlgorithms {
    fn decode(input: &[u8]) -> nom::IResult<&[u8], Self>
    where
        Self: Sized,
    {
        let (input, cookie) = <[u8; 16]>::decode(input)?;
        let (input, kex_algorithms) = <NameList>::decode(input)?;
        let (input, server_host_key_algorithms) = <NameList>::decode(input)?;
        let (input, encryption_algorithms_client_to_server) = <NameList>::decode(input)?;
        let (input, encryption_algorithms_server_to_client) = <NameList>::decode(input)?;
        let (input, mac_algorithms_client_to_server) = <NameList>::decode(input)?;
        let (input, mac_algorithms_server_to_client) = <NameList>::decode(input)?;
        let (input, compression_algorithms_client_to_server) = <NameList>::decode(input)?;
        let (input, compression_algorithms_server_to_client) = <NameList>::decode(input)?;
        let (input, languages_client_to_server) = <NameList>::decode(input)?;
        let (input, languages_server_to_client) = <NameList>::decode(input)?;
        let (input, first_kex_packet_follows) = <bool>::decode(input)?;
        let (input, reserved) = <u32>::decode(input)?;

        Ok((
            input,
            KexAlgorithms {
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
                first_kex_packet_follows,
                reserved,
            },
        ))
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        self.cookie.encode(buf);
        self.kex_algorithms.encode(buf);
        self.server_host_key_algorithms.encode(buf);
        self.encryption_algorithms_client_to_server.encode(buf);
        self.encryption_algorithms_server_to_client.encode(buf);
        self.mac_algorithms_client_to_server.encode(buf);
        self.mac_algorithms_server_to_client.encode(buf);
        self.compression_algorithms_client_to_server.encode(buf);
        self.compression_algorithms_server_to_client.encode(buf);
        self.languages_client_to_server.encode(buf);
        self.languages_server_to_client.encode(buf);
        self.first_kex_packet_follows.encode(buf);
        self.reserved.encode(buf);
    }
}

// When acting as server: "ext-info-s"
// When acting as client: "ext-info-c"
#[test]
fn parse_test_key_exchange_init_packet() {
    // \x00\x00\x05\xdc\x04\x14
    let mut payload = Data(b"\x14\x11\x58\xa5\x0f\xa6\x66\x70\x27\x00\x75\x6b\xd9\x62\xe5\xdc\xb2\
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
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec());
    payload.expect(message_code::SSH_MSG_KEXINIT);
    let kex_algorithms: KexAlgorithms = payload.get();
    let mut gen_packet = Data::new();
    gen_packet
        .put(&message_code::SSH_MSG_KEXINIT)
        .put(&kex_algorithms);
    assert!(payload.into_inner() == gen_packet.into_inner());
}
