use rand::Rng;

use super::client::SshClient;
use super::data::{Data, NameList};
use super::error::SshResult;
use super::session::Session;
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
    pub fn key_exchange_init(&mut self) -> SshResult<()> {
        // recv key algorithms
        let mut payload = self.recv()?;
        let server_kex_algorithms = KexAlgorithms::unpack(&mut payload);

        // send key algorithms
        let client_kex_algorithms = self.config.kex.clone();
        self.send(&client_kex_algorithms.pack())?;

        self.session
            .set_kex_algorithms(&client_kex_algorithms, &server_kex_algorithms);
        Ok(())
    }
}

impl KexAlgorithms {
    pub fn unpack(payload: &mut Data) -> Self {
        let message_code: u8 = payload.get();
        match message_code {
            message_code::SSH_MSG_KEXINIT => {}
            _ => {
                panic!("unexpected message code")
            }
        }

        KexAlgorithms {
            cookie: payload.get(),
            kex_algorithms: payload.get(),
            server_host_key_algorithms: payload.get(),
            encryption_algorithms_client_to_server: payload.get(),
            encryption_algorithms_server_to_client: payload.get(),
            mac_algorithms_client_to_server: payload.get(),
            mac_algorithms_server_to_client: payload.get(),
            compression_algorithms_client_to_server: payload.get(),
            compression_algorithms_server_to_client: payload.get(),
            languages_client_to_server: payload.get(),
            languages_server_to_client: payload.get(),
            first_kex_packet_follows: payload.get(),
            reserved: payload.get(),
        }
    }

    pub fn pack(&self) -> Data {
        let mut data = Data::new();
        data.put(&message_code::SSH_MSG_KEXINIT)
            .put(&self.cookie)
            .put(&self.kex_algorithms)
            .put(&self.server_host_key_algorithms)
            .put(&self.encryption_algorithms_client_to_server)
            .put(&self.encryption_algorithms_server_to_client)
            .put(&self.mac_algorithms_client_to_server)
            .put(&self.mac_algorithms_server_to_client)
            .put(&self.compression_algorithms_client_to_server)
            .put(&self.compression_algorithms_server_to_client)
            .put(&self.languages_client_to_server)
            .put(&self.languages_server_to_client)
            .put(&self.languages_server_to_client)
            .put(&self.first_kex_packet_follows);
        data
    }
}

// When acting as server: "ext-info-s"
// When acting as client: "ext-info-c"
#[test]
fn parse_test_key_exchange_init_packet() {
    // \x00\x00\x05\xdc\x04\x14
    let packet = b"\x14\x11\x58\xa5\x0f\xa6\x66\x70\x27\x00\x75\x6b\xd9\x62\xe5\xdc\xb2\
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
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    //\x00\x00\x00\x00";
    let mut payload = Data(packet.to_vec());
    let algo = KexAlgorithms::unpack(&mut payload);
    let gen_packet = algo.pack();
    assert!(packet[..] == gen_packet.into_inner()[..]);
}
