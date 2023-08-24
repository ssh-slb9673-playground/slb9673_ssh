use super::{client::SshClient, data::Mpint, error::SshResult, session::Session};
use crate::protocol::{
    data::{ByteString, Data, NameList},
    ssh2::message_code,
};

impl SshClient {
    pub fn user_auth(&mut self, session: &mut Session) -> SshResult<&[u8]> {
        self.service_request(session)?;
        let service_name: String = self.service_accept(session)?;
        println!("{:?}", service_name);
        self.userauth_request(session)?;
        self.userauth_accept(session)?;

        Ok(&[])
    }

    fn service_request(&mut self, session: &mut Session) -> SshResult<()> {
        let mut payload = Data::new();
        payload
            .put(&message_code::SSH_MSG_SERVICE_REQUEST)
            .put(&ByteString::from_str("ssh-userauth"));
        self.send(&payload.pack(session).seal())
    }

    fn service_accept(&mut self, session: &mut Session) -> SshResult<String> {
        let mut payload = self.recv()?.pack(session).unseal()?;
        let message_code: u8 = payload.get();
        match message_code {
            message_code::SSH_MSG_SERVICE_ACCEPT => {}
            _ => {
                panic!("unexpected message code")
            }
        }
        let service_name: String = payload.get();
        Ok(service_name)
    }

    fn userauth_request(&mut self, session: &mut Session) -> SshResult<()> {
        let mut payload = Data::new();
        let e = Mpint(vec![0x1, 0x00, 0x01]);
        let n = Mpint(vec![
            0x00, 0xcd, 0x0c, 0x77, 0x94, 0x63, 0x43, 0x55, 0x91, 0x4a, 0x5a, 0x20, 0x17, 0xc8,
            0x61, 0x3c, 0x4d, 0x3f, 0x94, 0xbc, 0x33, 0x97, 0x2a, 0x91, 0xdf, 0x13, 0xb6, 0x83,
            0x23, 0xf3, 0x67, 0x90, 0x6f, 0xc8, 0xab, 0xb6, 0xd7, 0xe8, 0x92, 0xe5, 0x28, 0xa2,
            0x70, 0x8d, 0x46, 0xa4, 0x1f, 0xb5, 0x34, 0xa9, 0x07, 0xf9, 0xa5, 0xf8, 0x35, 0x17,
            0xf5, 0xf6, 0x26, 0x96, 0x6e, 0x92, 0xdc, 0x17, 0x82, 0x97, 0x5f, 0x4c, 0x73, 0x23,
            0xfa, 0xb8, 0xdf, 0x15, 0x57, 0xe5, 0xaa, 0x9b, 0x1b, 0x31, 0xf4, 0x5f, 0xf7, 0x38,
            0xa7, 0x62, 0x36, 0xa4, 0x5e, 0xab, 0xd1, 0xe2, 0x38, 0x64, 0x5a, 0xbc, 0x67, 0x06,
            0x16, 0x91, 0x78, 0x9b, 0x3b, 0xdc, 0x4e, 0xa2, 0x32, 0x2b, 0x8a, 0x73, 0xaf, 0xf8,
            0x49, 0x9c, 0xba, 0x02, 0x11, 0xa5, 0x63, 0x59, 0x66, 0x90, 0x46, 0x70, 0x2b, 0xb8,
            0xf8, 0x75, 0x9a, 0xe0, 0x93, 0x78, 0xf6, 0xa6, 0x0b, 0xfb, 0x6b, 0x63, 0x57, 0x4c,
            0x66, 0x9d, 0xe4, 0x2e, 0x14, 0x37, 0x06, 0xb1, 0xf8, 0x6d, 0x9f, 0x05, 0xf5, 0xc3,
            0xdb, 0x93, 0x42, 0x88, 0x97, 0x91, 0xb9, 0xe1, 0x7b, 0xde, 0xe7, 0x54, 0x53, 0x02,
            0x4d, 0x45, 0xd8, 0x94, 0x0b, 0x14, 0x57, 0xf7, 0xa3, 0x2a, 0x12, 0xb5, 0x41, 0x8a,
            0xf0, 0xf4, 0x39, 0xe4, 0xac, 0xac, 0xfd, 0x0d, 0x99, 0xee, 0x3e, 0xe4, 0x69, 0xd4,
            0xdd, 0x64, 0x4b, 0xe6, 0x24, 0xd6, 0xa2, 0xf0, 0xba, 0x0c, 0xac, 0xa2, 0xe5, 0x91,
            0x6b, 0x65, 0xe2, 0x03, 0xf8, 0x74, 0x99, 0x50, 0xa2, 0x5c, 0x91, 0xcb, 0xeb, 0xd0,
            0x4a, 0x08, 0xa3, 0x77, 0xd0, 0xf3, 0x1a, 0xee, 0x49, 0xdd, 0x6b, 0xa5, 0x7a, 0x45,
            0xaa, 0xe9, 0x4f, 0x29, 0x17, 0x9e, 0x10, 0x65, 0x06, 0xea, 0x63, 0xc8, 0x0b, 0x24,
            0x92, 0x66, 0xf0, 0xbe, 0x0f, 0xee, 0x4f, 0x28, 0xaf, 0xec, 0x76, 0xd9, 0xce, 0x37,
            0xab, 0x0b, 0xc3, 0x0a, 0xeb, 0x50, 0x9b, 0x5e, 0x39, 0x0e, 0x3e, 0x5d, 0x09, 0xc3,
            0xc7, 0x78, 0x93, 0xe5, 0x94, 0x1c, 0x45, 0x51, 0xf2, 0xfc, 0x87, 0x6d, 0xf2, 0xbe,
            0xe0, 0x30, 0x14, 0xcd, 0x36, 0xc3, 0xfb, 0xd6, 0x59, 0xec, 0xd6, 0xf7, 0x95, 0x3e,
            0x47, 0x04, 0x5c, 0x2b, 0x14, 0x03, 0xb3, 0xae, 0x9d, 0x1d, 0xe3, 0x3a, 0x7a, 0x9f,
            0xb5, 0x32, 0x0d, 0x57, 0x20, 0x1f, 0x9e, 0xe5, 0x69, 0x82, 0x1f, 0x54, 0x55, 0x81,
            0xe5, 0xc9, 0x4d, 0x10, 0x5e, 0xdc, 0xdd, 0x84, 0x27, 0xbe, 0x5c, 0x02, 0x8f, 0x69,
            0xac, 0x4d, 0xdd, 0x0d, 0xb7, 0x8f, 0xa3, 0x75, 0x60, 0x21, 0x30, 0x34, 0xf8, 0xbb,
            0x7d, 0xa6, 0x0b, 0x67, 0x00, 0x51, 0x3a, 0xc6, 0xd1, 0xba, 0x45, 0x41, 0x04, 0xc7,
            0x30, 0x76, 0x4b, 0xb0, 0x8c, 0x5d, 0xbb,
        ]);
        payload
            .put(&message_code::SSH_MSG_USERAUTH_REQUEST)
            .put(&"anko".to_string())
            .put(&"ssh-connection".to_string())
            .put(&"publickey".to_string())
            .put(&false)
            // .put(&"ssh-rsa".to_string())
            .put(&"rsa-sha2-256".to_string())
            .put(&e)
            .put(&n);

        self.send(&payload.pack(session).seal())
    }

    pub fn userauth_accept(&mut self, session: &mut Session) -> SshResult<()> {
        let mut payload = self.recv()?.pack(session).unseal()?;
        let message_code: u8 = payload.get();
        match message_code {
            message_code::SSH_MSG_SERVICE_ACCEPT => {
                let service_name: ByteString = payload.get();
                println!("{:?}", String::from_utf8(service_name.0));
            }
            message_code::SSH_MSG_USERAUTH_FAILURE => {
                let auth: NameList = payload.get();
                let success: bool = payload.get();
                println!("auth: {:?}", auth);
                println!("success: {}", success)
            }
            message_code::SSH_MSG_USERAUTH_SUCCESS => {}
            message_code::SSH_MSG_USERAUTH_BANNER => {
                let message: ByteString = payload.get();
                let language_tag: ByteString = payload.get();
            }
            message_code::SSH2_MSG_USERAUTH_PK_OK => {
                let pubkey_algo: ByteString = payload.get();
                let pubkey_blob: ByteString = payload.get();
            }
            _ => {
                panic!("unexpected message code")
            }
        }
        Ok(())
    }

    fn user_request_recv(&mut self, session: &mut Session) -> SshResult<()> {
        let mut payload = self.recv()?.pack(session).unseal()?;
        let message_code: u8 = payload.get();
        match message_code {
            message_code::SSH_MSG_SERVICE_REQUEST => {
                let service_name: String = payload.get();
            }
            message_code::SSH_MSG_USERAUTH_REQUEST => {
                let user_name: String = payload.get();
                let service_name: String = payload.get();
                let method_name: String = payload.get();
                match method_name.as_str() {
                    "publickey" => {
                        let is_signature: bool = payload.get();
                        let pubkey_algo: String = payload.get();
                        let pubkey_blob: ByteString = payload.get();
                        let signature: ByteString = payload.get();
                    }
                    "password" => {
                        let is_first: bool = payload.get();
                        if is_first {
                            let password: String = payload.get();
                        } else {
                            let old_password: String = payload.get();
                            let new_password: String = payload.get();
                        }
                    }
                    "hostbased" => {
                        let host_pubkey_algo: String = payload.get();
                        let host_pubkey_cert: ByteString = payload.get();
                        let hostname: String = payload.get();
                        let username: String = payload.get();
                        let signature: ByteString = payload.get();
                    }
                    "none" => {
                        panic!("none auth");
                    }
                    _ => {
                        panic!("unknown");
                    }
                }
            }
            _ => {}
        }
        Ok(())
        // match message_code {
        //     message_code::SSH_MSG_DISCONNECT => {
        //         let disconnect_code: u32 = payload.get();
        //         let description: String = payload.get();
        //         let language_tag: String = payload.get();
        //     }
        //     message_code::SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ => {
        //         let prompt: String = payload.get();
        //         let language_tag: String = payload.get();
        //     }
        //     _ => {
        //         panic!("unexpected message code")
        //     }
        // }
    }
}
