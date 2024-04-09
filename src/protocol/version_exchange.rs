use super::client::SshClient;
use super::data::{Data, DataType};
use nom::bytes::complete::{tag, take_until};

// SSH_protoversion_softwareversion SP comments CR LF
#[derive(Debug, Clone, PartialEq)]
pub struct Version {
    pub version: String,
    pub crnl: bool,
}

impl Version {
    pub fn set_crnl(&mut self, crnl: bool) -> &Self {
        self.crnl = crnl;
        self
    }
}

impl SshClient {
    pub fn version_exchange(&mut self) -> anyhow::Result<()> {
        let client_vesrion: Data = Data::new().put(&self.version);
        self.send(&client_vesrion)?;
        let server_version: Version = self.recv()?.get();

        self.session.set_version(&self.version, &server_version);
        println!("client_version: {:?}", self.version);
        println!("server_version: {:?}", server_version);

        Ok(())
    }
}

impl DataType for Version {
    fn decode(input: &[u8]) -> nom::IResult<&[u8], Self>
    where
        Self: Sized,
    {
        let (input, version) = take_until("\r\n")(input)?;
        let (input, _) = tag("\r\n")(input)?;
        Ok((
            input,
            Version {
                version: String::from_utf8(version.to_vec()).unwrap(),
                crnl: true,
            },
        ))
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend(self.version.as_bytes());
        if self.crnl {
            buf.extend("\r\n".as_bytes());
        }
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
