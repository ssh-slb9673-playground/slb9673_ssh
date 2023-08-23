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
    pub fn key_exchange_init(
        &mut self,
        session: &mut Session,
    ) -> SshResult<(KexAlgorithms, KexAlgorithms)> {
        // recv key algorithms
        let mut payload = self.recv()?.pack(session).unseal()?;
        let server_kex_algorithms = KexAlgorithms::unpack(&mut payload);

        // send key algorithms
        let client_kex_algorithms = KexAlgorithms::client_kex_algorithms();
        self.send(&client_kex_algorithms.pack().pack(session).seal())?;

        Ok((client_kex_algorithms, server_kex_algorithms))
    }
}

impl KexAlgorithms {
    pub fn unpack(input: &mut Data) -> Self {
        let message_code: u8 = input.get();
        assert!(message_code == message_code::SSH_MSG_KEXINIT);

        KexAlgorithms {
            cookie: input.get(),
            kex_algorithms: input.get(),
            server_host_key_algorithms: input.get(),
            encryption_algorithms_client_to_server: input.get(),
            encryption_algorithms_server_to_client: input.get(),
            mac_algorithms_client_to_server: input.get(),
            mac_algorithms_server_to_client: input.get(),
            compression_algorithms_client_to_server: input.get(),
            compression_algorithms_server_to_client: input.get(),
            languages_client_to_server: input.get(),
            languages_server_to_client: input.get(),
            first_kex_packet_follows: input.get(),
            reserved: input.get(),
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

    pub fn client_kex_algorithms() -> KexAlgorithms {
        KexAlgorithms {
            cookie: rand::thread_rng().gen::<[u8; 16]>(),
            kex_algorithms: vec!["curve25519-sha256".to_string()],
            server_host_key_algorithms: vec!["rsa-sha2-256".to_string()],
            encryption_algorithms_client_to_server: vec![
                "chacha20-poly1305@openssh.com".to_string()
            ],
            encryption_algorithms_server_to_client: vec![
                "chacha20-poly1305@openssh.com".to_string()
            ],
            mac_algorithms_client_to_server: vec!["hmac-sha2-256".to_string()],
            mac_algorithms_server_to_client: vec!["hmac-sha2-256".to_string()],
            compression_algorithms_client_to_server: vec!["none".to_string()],
            compression_algorithms_server_to_client: vec!["none".to_string()],
            languages_client_to_server: vec![],
            languages_server_to_client: vec![],
            first_kex_packet_follows: false,
            reserved: 0,
        }
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
