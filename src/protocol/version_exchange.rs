use nom::bytes::complete::{tag, take_until};
use nom::AsBytes;
use nom::IResult;

use super::client::SshClient;
use super::error::SshError;
use crate::protocol::data::DataType;

// SSH_protoversion_softwareversion SP comments CR LF
#[derive(Debug, Clone, PartialEq)]
pub struct Version {
    version: String,
    crnl: bool,
}

impl Version {
    pub fn new(ssh_protoversion_softwareversion: &str, comments: Option<&str>) -> Self {
        let mut version = ssh_protoversion_softwareversion.to_string();
        if let Some(comments) = &comments {
            version += " ";
            version += comments;
        }
        Version {
            version,
            crnl: true,
        }
    }

    pub fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, version) = take_until("\r\n")(input)?;
        let (input, _) = tag("\r\n")(input)?;
        Ok((
            input,
            Version {
                version: String::from_utf8(version.to_vec()).unwrap(),
                crnl: false,
            },
        ))
    }

    pub fn generate(&self, crnl: bool) -> Vec<u8> {
        let mut payload = self.version.clone();
        if crnl {
            payload += "\r\n";
        }
        payload.into_bytes()
    }
}

impl SshClient {
    pub fn version_exchange(&mut self) -> Result<(Version, Version), SshError> {
        // send version
        let mut packet = Vec::new();
        let client_version = Version::new("SSH-2.0-OpenSSH_8.9p1", Some("Ubuntu-3ubuntu0.1"));
        client_version.generate(true).as_bytes().encode(&mut packet);
        self.send(&packet)?;

        // recv version
        let (_input, server_version) = Version::from_bytes(&self.recv()?.into_inner())
            .map_err(|_| SshError::RecvError("version".to_string()))?;

        Ok((client_version, server_version))
    }
}

#[test]
fn parse_ssh_version() {
    let packet = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n";
    let (input, version_from_packet) = Version::from_bytes(packet).unwrap();
    let version = Version::new("SSH-2.0-OpenSSH_8.9p1", Some("Ubuntu-3ubuntu0.1"));
    assert_eq!(version, version_from_packet);
    println!("{:?}", input);
    println!("{:?}", version_from_packet);
    let packet = b"SSH-2.0-babeld-dc5ec9be\r\n";
    let version = Version::from_bytes(packet);
    println!("{:?}", version);
}
// 00000000  53 53 48 2d 32 2e 30 2d  4f 70 65 6e 53 53 48 5f   SSH-2.0- OpenSSH_
// 00000010  38 2e 39 70 31 20 55 62  75 6e 74 75 2d 33 75 62   8.9p1 Ub untu-3ub
// 00000020  75 6e 74 75 30 2e 31 0d  0a                        untu0.1. .
