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

struct Authentication {
    user_name: String,
    service_name: String,
    method_name: Method,
    et: boolean,
    algorithm_name: a,
    public_key_blob: a,
}

// SSH_MSG_USERAUTH_REQUEST            50
// SSH_MSG_USERAUTH_FAILURE            51
// SSH_MSG_USERAUTH_SUCCESS            52
