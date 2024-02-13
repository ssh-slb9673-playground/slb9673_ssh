use super::client::SshClient;
use crate::{
    crypto::public_key::rsa::RsaSha256,
    protocol::{
        data::{ByteString, Data, NameList},
        ssh2::message_code,
    },
};
use anyhow::Result;

impl SshClient {
    pub fn user_auth(&mut self) -> Result<()> {
        self.service_request()?;
        let service_name: String = self.service_accept()?;
        println!("{:?}", service_name);
        self.userauth_request()?;
        self.userauth_accept()?;

        Ok(())
    }

    fn service_request(&mut self) -> Result<()> {
        let payload = Data::new()
            .put(&message_code::SSH_MSG_SERVICE_REQUEST)
            .put(&ByteString::from_str("ssh-userauth"));
        self.send(&payload)
    }

    fn service_accept(&mut self) -> Result<String> {
        let mut payload = self.recv()?;
        let message_code: u8 = payload.get();
        assert!(message_code == message_code::SSH_MSG_SERVICE_ACCEPT);
        let service_name: String = payload.get();
        Ok(service_name)
    }

    fn userauth_request(&mut self) -> Result<()> {
        let rsa = RsaSha256::read_from_file()?;

        let data = Data::new()
            .put(&ByteString(self.session.get_keys().exchange_hash)) // session identifier
            .put(&message_code::SSH_MSG_USERAUTH_REQUEST)
            .put(&self.config.username)
            .put(&self.service_name)
            .put(&"publickey".to_string())
            .put(&true)
            .put(&"rsa-sha2-256".to_string())
            .put(&rsa.public_key_blob());

        let payload = Data::new()
            .put(&message_code::SSH_MSG_USERAUTH_REQUEST)
            .put(&self.config.username)
            .put(&self.service_name)
            .put(&"publickey".to_string())
            .put(&true)
            .put(&"rsa-sha2-256".to_string())
            .put(&rsa.public_key_blob())
            .put(&rsa.signature_blob(data));

        self.send(&payload)
    }

    pub fn userauth_accept(&mut self) -> Result<()> {
        let mut payload = self.recv()?;
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
                let message: String = payload.get();
                let language_tag: String = payload.get();
                println!("message: {}", message);
                println!("language: {}", language_tag);
            }
            message_code::SSH2_MSG_USERAUTH_PK_OK => {
                let pubkey_algo: String = payload.get();
                let pubkey_blob: ByteString = payload.get();
                println!("pubkey: {} {:?}", pubkey_algo, pubkey_blob.0);
            }
            _ => {
                panic!("unexpected message code")
            }
        }
        Ok(())
    }

    // fn user_request_recv(&mut self) -> Result<()> {
    //     let mut payload = self.recv()?;
    //     let message_code: u8 = payload.get();
    //     match message_code {
    //         message_code::SSH_MSG_SERVICE_REQUEST => {
    //             let service_name: String = payload.get();
    //         }
    //         message_code::SSH_MSG_USERAUTH_REQUEST => {
    //             let user_name: String = payload.get();
    //             let service_name: String = payload.get();
    //             let method_name: String = payload.get();
    //             match method_name.as_str() {
    //                 "publickey" => {
    //                     let is_signature: bool = payload.get();
    //                     let pubkey_algo: String = payload.get();
    //                     let pubkey_blob: ByteString = payload.get();
    //                     let signature: ByteString = payload.get();
    //                 }
    //                 "password" => {
    //                     let is_first: bool = payload.get();
    //                     if is_first {
    //                         let password: String = payload.get();
    //                     } else {
    //                         let old_password: String = payload.get();
    //                         let new_password: String = payload.get();
    //                     }
    //                 }
    //                 "hostbased" => {
    //                     let host_pubkey_algo: String = payload.get();
    //                     let host_pubkey_cert: ByteString = payload.get();
    //                     let hostname: String = payload.get();
    //                     let username: String = payload.get();
    //                     let signature: ByteString = payload.get();
    //                 }
    //                 "none" => {
    //                     panic!("none auth");
    //                 }
    //                 _ => {
    //                     panic!("unknown");
    //                 }
    //             }
    //         }
    //         _ => {}
    //     }
    //     Ok(())
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
    // }
}
