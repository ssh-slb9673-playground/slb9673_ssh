use nom::{bytes::complete::take_until, IResult};

// SSH_protoversion_softwareversion SP comments CR LF
pub struct Version {
    ssh_protoversion_softwareversion: String,
    comments: String,
}

impl Version {
    pub fn new(ssh_protoversion_softwareversion: String, comments: String) -> Self {
        Version {
            ssh_protoversion_softwareversion,
            comments,
        }
    }

    pub fn parse_version(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, ssh_protoversion_softwareversion) = take_until(" ")(input)?;
        let ssh_protoversion_softwareversion =
            String::from_utf8(ssh_protoversion_softwareversion.to_vec()).unwrap();
        let (input, comments) = take_until("\r\n")(input)?;
        let comments = String::from_utf8(comments.to_vec()).unwrap();

        Ok((
            input,
            Version {
                ssh_protoversion_softwareversion,
                comments,
            },
        ))
    }

    pub fn generate_version(&self) -> Vec<u8> {
        format!(
            "{} {}\r\n",
            self.ssh_protoversion_softwareversion, self.comments
        )
        .as_bytes()
        .to_vec()
    }
}
