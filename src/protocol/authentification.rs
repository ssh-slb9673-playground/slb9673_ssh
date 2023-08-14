// "publickey"             REQUIRED
// "password"              OPTIONAL
// "hostbased"             OPTIONAL
// "none"                  NOT RECOMMENDED

// byte      SSH_MSG_USERAUTH_REQUEST
// string    user name in ISO-10646 UTF-8 encoding [RFC3629]
// string    service name in US-ASCII
// string    "publickey"
// boolean   FALSE
// string    public key algorithm name
// string    public key blob

// byte      SSH_MSG_USERAUTH_REQUEST
// string    user name
// string    service name
// string    "password"
// boolean   FALSE
// string    plaintext password in ISO-10646 UTF-8 encoding [RFC3629]

// byte      SSH_MSG_USERAUTH_REQUEST
// string    user name
// string    service name
// string    "hostbased"
// string    public key algorithm for host key
// string    public host key and certificates for client host
// string    client host name expressed as the FQDN in US-ASCII
// string    user name on the client host in ISO-10646 UTF-8 encoding [RFC3629]
// string    signature

use super::{
    session::Session,
    ssh2::MessageCode,
    utils::{ByteString, DataType},
};

enum Method {
    publickey,
    password,
    hostbased,
    none,
}

pub struct Authentication {
    user_name: ByteString,
    service_name: ByteString,
    method_name: ByteString,
    pubkey_name: ByteString,
}

impl Authentication {
    pub fn new(
        user_name: Vec<u8>,
        service_name: Vec<u8>,
        method_name: Vec<u8>,
        pubkey_name: Vec<u8>,
    ) -> Self {
        Authentication {
            user_name: ByteString(user_name),
            service_name: ByteString(service_name),
            method_name: ByteString(method_name),
            pubkey_name: ByteString(pubkey_name),
        }
    }

    pub fn generate(&self, session: &mut Session) -> Vec<u8> {
        let mut packet = Vec::new();
        MessageCode::SSH_MSG_USERAUTH_REQUEST
            .to_u8()
            .encode(&mut packet);
        self.user_name.encode(&mut packet);
        self.service_name.encode(&mut packet);
        self.method_name.encode(&mut packet);
        false.encode(&mut packet);
        // public key algorithm name
        self.pubkey_name.encode(&mut packet);
        // public key blob
        packet
    }
}
