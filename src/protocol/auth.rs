use super::{client::SshClient, data::DataType};
use crate::{
    crypto::public_key::rsa::RsaSha256,
    protocol::{
        data::{ByteString, Data, NameList},
        ssh2::message_code,
    },
};

struct PublicKeyAuthenticationMethod {
    username: String,
    service_name: String,
    method_name: String,
    with_authentication: bool,
    publickey_algorithm_name: String,
    publickey_blob: ByteString,
}

impl DataType for PublicKeyAuthenticationMethod {
    fn decode(input: &[u8]) -> nom::IResult<&[u8], Self>
    where
        Self: Sized,
    {
        let (input, username) = <String>::decode(input)?;
        let (input, service_name) = <String>::decode(input)?;
        let (input, method_name) = <String>::decode(input)?;
        let (input, with_authentication) = <bool>::decode(input)?;
        let (input, publickey_algorithm_name) = <String>::decode(input)?;
        let (input, publickey_blob) = <ByteString>::decode(input)?;

        Ok((
            input,
            PublicKeyAuthenticationMethod {
                username,
                service_name,
                method_name,
                with_authentication,
                publickey_algorithm_name,
                publickey_blob,
            },
        ))
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        self.username.encode(buf);
        self.service_name.encode(buf);
        self.method_name.encode(buf);
        self.with_authentication.encode(buf);
        self.publickey_algorithm_name.encode(buf);
        self.publickey_blob.encode(buf);
    }
}

impl SshClient {
    pub fn user_auth(&mut self) -> anyhow::Result<()> {
        self.service_request()?;
        let service_name: String = self.service_accept()?;
        println!("service accepted: {}", service_name);
        self.userauth_request()?;
        self.userauth_accept()?;
        println!("userauth accepted");

        Ok(())
    }

    fn service_request(&mut self) -> anyhow::Result<()> {
        let mut payload = Data::new();
        payload
            .put(&message_code::SSH_MSG_SERVICE_REQUEST)
            .put(&ByteString::from_str("ssh-userauth"));
        self.send(&payload)
    }

    fn service_accept(&mut self) -> anyhow::Result<String> {
        let mut payload = self.recv()?;
        payload.expect(message_code::SSH_MSG_SERVICE_ACCEPT);
        let service_name: String = payload.get();
        Ok(service_name)
    }

    fn userauth_request(&mut self) -> anyhow::Result<()> {
        let rsa = RsaSha256::read_from_file()?;

        let publickey_method = PublicKeyAuthenticationMethod {
            username: self.config.username.clone(),
            service_name: self.config.service_name.clone(),
            method_name: "publickey".to_string(),
            with_authentication: true,
            publickey_algorithm_name: "rsa-sha2-256".to_string(),
            publickey_blob: rsa.public_key_blob(),
        };

        let mut data = Data::new();
        data.put(&ByteString(self.session.get_keys().exchange_hash)) // session identifier
            .put(&message_code::SSH_MSG_USERAUTH_REQUEST)
            .put(&publickey_method);

        let mut payload = Data::new();
        payload
            .put(&message_code::SSH_MSG_USERAUTH_REQUEST)
            .put(&publickey_method)
            .put(&rsa.signature_blob(data));

        self.send(&payload)
    }

    pub fn userauth_accept(&mut self) -> anyhow::Result<()> {
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

    // fn user_request_recv(&mut self) -> anyhow::Result<()> {
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
