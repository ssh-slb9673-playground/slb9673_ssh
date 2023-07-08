fn version_exchange() -> String {
    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1".to_string()
}

// [hasshServerAlgorithms [truncated]: curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256;chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gc]
// [hasshServer: d5037e2b5d0a751478bc339d1cf024a8]

/*
- hmac-sha1 REQUIRED HMAC-SHA1 (digest length = key length = 20)
- hmac-sha1-96 RECOMMENDED first 96 bits of HMAC-SHA1 (digest length = 12, key length = 20)
*/

/*
ssh-dss REQUIRED sign Raw DSS Key
ssh-rsa RECOMMENDED sign Raw RSA Key
 */
