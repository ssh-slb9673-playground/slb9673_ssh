use nom::bytes::complete::{tag, take_until};
use nom::error::Error;
use nom::AsBytes;

use super::client::SshClient;
use super::data::Data;
use super::error::{SshError, SshResult};

// SSH_protoversion_softwareversion SP comments CR LF
#[derive(Debug, Clone, PartialEq)]
pub struct Version {
    version: String,
    crnl: bool,
}

impl SshClient {
    pub fn version_exchange(&mut self) -> SshResult<(Version, Version)> {
        let client_version = Version::client_version();
        self.send_version(&client_version)?;
        let server_version = self.recv_version()?;

        Ok((client_version, server_version))
    }

    fn send_version(&mut self, client_version: &Version) -> SshResult<()> {
        let mut packet = Data::new();
        packet.put(&client_version.pack().as_bytes());
        self.send(&packet.into_inner())
    }

    fn recv_version(&mut self) -> SshResult<Version> {
        let packet = &self.recv()?.into_inner();
        Ok(Version::unpack(packet)?)
    }
}

impl Version {
    pub fn set_crnl(&mut self, crnl: bool) -> &Self {
        self.crnl = crnl;
        self
    }

    pub fn client_version() -> Self {
        Version {
            version: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1".to_string(),
            crnl: true,
        }
    }

    pub fn unpack(input: &[u8]) -> SshResult<Self> {
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

#[test]
fn parse_ssh_version() {
    let packet = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n";
    let version_from_packet = Version::unpack(packet).unwrap();
    let version = Version::client_version();
    assert_eq!(version, version_from_packet);
    println!("{:?}", version_from_packet);
    let packet = b"SSH-2.0-babeld-dc5ec9be\r\n";
    let version = Version::unpack(packet);
    println!("{:?}", version);
}
// 00000000  53 53 48 2d 32 2e 30 2d  4f 70 65 6e 53 53 48 5f   SSH-2.0- OpenSSH_
// 00000010  38 2e 39 70 31 20 55 62  75 6e 74 75 2d 33 75 62   8.9p1 Ub untu-3ub
// 00000020  75 6e 74 75 30 2e 31 0d  0a                        untu0.1. .
