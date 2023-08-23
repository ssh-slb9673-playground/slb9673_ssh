use super::{client::SshClient, error::SshResult, session::Session};
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
        assert!(message_code == message_code::SSH_MSG_SERVICE_ACCEPT);
        let service_name: String = payload.get();
        Ok(service_name)
    }

    fn userauth_request(&mut self, session: &mut Session) -> SshResult<()> {
        let mut payload = Data::new();
        payload
            .put(&message_code::SSH_MSG_USERAUTH_REQUEST)
            .put(&"anko".to_string())
            .put(&"ssh-connection".to_string())
            .put(&"publickey".to_string())
            .put(&true)
            .put(&"rsa-sha2-256".to_string())
            .put(&ByteString::from_str("signature"));
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
            message_code::SSH2_MSG_USERAUTH_PK_OK => {
                let pubkey_algo: ByteString = payload.get();
                let pubkey_blob: ByteString = payload.get();
            }
            message_code::SSH_MSG_USERAUTH_FAILURE => {
                let auth: NameList = payload.get();
                let success: bool = payload.get();
                println!("{:?} {}", auth, success);
            }
            message_code::SSH_MSG_USERAUTH_SUCCESS => {}
            message_code::SSH_MSG_USERAUTH_BANNER => {
                let message: ByteString = payload.get();
                let language_tag: ByteString = payload.get();
            }
            _ => {
                panic!("unexpected message code")
            }
        }
        // let mut payload = self.recv()?.pack(session).unseal()?;
        // let message_code: u8 = payload.get();
        // match message_code {
        //     message_code::SSH_MSG_DISCONNECT => {
        //         let disconnect_code: u32 = payload.get();
        //         let description: String = payload.get();
        //         let language_tag: String = payload.get();
        //     }
        //     message_code::SSH_MSG_SERVICE_REQUEST => {
        //         let service_name: String = payload.get();
        //     }
        //     message_code::SSH_MSG_SERVICE_ACCEPT => {
        //         let service_name: String = payload.get();
        //         println!("{:?}", service_name);
        //     }
        //     message_code::SSH_MSG_USERAUTH_REQUEST => {
        //         let user_name: String = payload.get();
        //         let service_name: String = payload.get();
        //         let method_name: String = payload.get();
        //         match method_name.as_str() {
        //             "publickey" => {
        //                 let is_signature: bool = payload.get();
        //                 let pubkey_algo: String = payload.get();
        //                 let pubkey_blob: ByteString = payload.get();
        //                 let signature: ByteString = payload.get();
        //             }
        //             "password" => {
        //                 let is_first: bool = payload.get();
        //                 if is_first {
        //                     let password: String = payload.get();
        //                 } else {
        //                     let old_password: String = payload.get();
        //                     let new_password: String = payload.get();
        //                 }
        //             }
        //             "hostbased" => {
        //                 let host_pubkey_algo: String = payload.get();
        //                 let host_pubkey_cert: ByteString = payload.get();
        //                 let hostname: String = payload.get();
        //                 let username: String = payload.get();
        //                 let signature: ByteString = payload.get();
        //             }
        //             "none" => {
        //                 panic!("none auth");
        //             }
        //             _ => {
        //                 panic!("unknown");
        //             }
        //         }
        //     }
        //     message_code::SSH_MSG_USERAUTH_FAILURE => {
        //         println!("failure");
        //         let auth: NameList = payload.get();
        //         let success: bool = payload.get();
        //     }
        //     message_code::SSH_MSG_USERAUTH_SUCCESS => {}
        //     message_code::SSH_MSG_USERAUTH_BANNER => {
        //         let message: String = payload.get();
        //         let language_tag: String = payload.get();
        //     }
        //     message_code::SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ => {
        //         let prompt: String = payload.get();
        //         let language_tag: String = payload.get();
        //     }
        //     message_code::SSH2_MSG_USERAUTH_PK_OK => {
        //         let pubkey_algo: String = payload.get();
        //         let pubkey_blob: ByteString = payload.get();
        //     }
        //     _ => {
        //         panic!("unexpected message code")
        //     }
        // }
        Ok(())
    }
}
