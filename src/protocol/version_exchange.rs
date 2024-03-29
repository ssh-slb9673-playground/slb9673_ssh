use super::client::SshClient;
use super::error::SshError;
use anyhow::Result;
use nom::bytes::complete::{tag, take_until};
use nom::error::Error;
use nom::AsBytes;

// SSH_protoversion_softwareversion SP comments CR LF
#[derive(Debug, Clone, PartialEq)]
pub struct Version {
    pub version: String,
    pub crnl: bool,
}

impl SshClient {
    pub fn version_exchange(&mut self) -> Result<()> {
        let client_version = self.version.clone();
        self.send_version(&client_version)?;
        println!("client_version: {:?}", client_version);

        let server_version = self.recv_version()?;
        self.session.set_version(&client_version, &server_version);
        println!("server_version: {:?}", server_version);

        Ok(())
    }

    pub fn send_version(&mut self, client_version: &Version) -> Result<()> {
        self.client.send(&client_version.pack().as_bytes())
    }

    pub fn recv_version(&mut self) -> Result<Version> {
        Ok(Version::unpack(&self.client.recv()?)?)
    }
}

impl Version {
    pub fn set_crnl(&mut self, crnl: bool) -> &Self {
        self.crnl = crnl;
        self
    }

    pub fn unpack(input: &[u8]) -> Result<Self> {
        let (input, version) = take_until("\r\n")(input)
            .map_err(|_: nom::Err<Error<&[u8]>>| SshError::RecvError("version".to_string()))?;
        let (_input, _) = tag("\r\n")(input)
            .map_err(|_: nom::Err<Error<&[u8]>>| SshError::RecvError("version".to_string()))?;
        Ok(Version {
            version: String::from_utf8(version.to_vec()).unwrap(),
            crnl: true,
        })
    }

    pub fn pack(&self) -> Vec<u8> {
        let mut payload = self.version.clone();
        if self.crnl {
            payload += "\r\n";
        }
        payload.into_bytes()
    }
}

// #[test]
// fn parse_ssh_version() {
//     let packet = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n";
//     let version_from_packet = Version::unpack(packet).unwrap();
//     let version = Version::client_version();
//     assert_eq!(version, version_from_packet);
//     println!("{:?}", version_from_packet);
//     let packet = b"SSH-2.0-babeld-dc5ec9be\r\n";
//     let version = Version::unpack(packet);
//     println!("{:?}", version);
// }
// 00000000  53 53 48 2d 32 2e 30 2d  4f 70 65 6e 53 53 48 5f   SSH-2.0- OpenSSH_
// 00000010  38 2e 39 70 31 20 55 62  75 6e 74 75 2d 33 75 62   8.9p1 Ub untu-3ub
// 00000020  75 6e 74 75 30 2e 31 0d  0a                        untu0.1. .
