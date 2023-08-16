use std::{
    error::Error,
    fmt::{self, write},
    io,
};

#[derive(Debug)]
pub enum SshError {
    ParseError,
    IoError(io::Error),
    SshError(String),
    SendError(String),
    RecvError(String),
    Timeout,
}

impl fmt::Display for SshError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SshError::ParseError => write!(f, "parse error"),
            SshError::SshError(e) => write!(f, "{}", e),
            SshError::IoError(v) => write!(f, "{}", v),
            SshError::SendError(e) => write!(f, "{}", e),
            SshError::RecvError(e) => write!(f, "{}", e),
            SshError::Timeout => write!(f, "time out."),
        }
    }
}

impl Error for SshError {}
