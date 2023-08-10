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

use super::{ssh2::MessageCode, utils::generate_string};

enum Method {
    publickey,
    password,
    hostbased,
    none,
}

pub struct Authentication {
    user_name: String,
    service_name: String,
    method_name: String,
}

impl Authentication {
    pub fn new(user_name: &str, service_name: &str, method_name: &str) -> Self {
        Authentication {
            user_name: user_name.to_string(),
            service_name: service_name.to_string(),
            method_name: method_name.to_string(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend(vec![MessageCode::SSH_MSG_USERAUTH_REQUEST.to_u8()]);
        packet.extend(generate_string(self.user_name.as_bytes()));
        packet.extend(generate_string(self.service_name.as_bytes()));
        packet.extend(generate_string(self.method_name.as_bytes()));
        packet
    }
}
