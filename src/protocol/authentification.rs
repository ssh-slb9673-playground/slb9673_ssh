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
    pub fn generate_authentication(&self) -> Vec<u8> {
        let mut packet = Vec::new();
        // SSH_MSG_USERAUTH_REQUEST
        packet.extend(vec![50]);
        packet.extend(self.user_name.clone().into_bytes());
        packet.extend(self.service_name.clone().into_bytes());
        packet.extend(self.method_name.clone().into_bytes());
        packet
    }
}

// SSH_MSG_USERAUTH_REQUEST            50
// SSH_MSG_USERAUTH_FAILURE            51
// SSH_MSG_USERAUTH_SUCCESS            52
