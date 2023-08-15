use super::{
    session::Session,
    ssh2::MessageCode,
    utils::{ByteString, DataType},
};

pub struct Authentication {
    user_name: ByteString,
    service_name: ByteString,
    method_name: ByteString, // publickey, password, hostbased, none
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
        let mut payload = Vec::new();
        MessageCode::SSH_MSG_USERAUTH_REQUEST
            .to_u8()
            .encode(&mut payload);
        self.user_name.encode(&mut payload);
        self.service_name.encode(&mut payload);
        self.method_name.encode(&mut payload);
        false.encode(&mut payload);
        // public key
        // string    public key algorithm name
        // string    public key blob
        self.pubkey_name.encode(&mut payload);
        // password
        // string    plaintext password in ISO-10646 UTF-8 encoding [RFC3629]
        payload
    }
}

// byte      SSH_MSG_USERAUTH_REQUEST
// string    user name
// string    service name
// string    "hostbased"
// string    public key algorithm for host key
// string    public host key and certificates for client host
// string    client host name expressed as the FQDN in US-ASCII
// string    user name on the client host in ISO-10646 UTF-8 encoding [RFC3629]
// string    signature
