use crate::protocol::{client::SshClient, data::Data, ssh2::message_code};
use anyhow::Result;

pub struct Channel<'a> {
    client: &'a mut SshClient,
    pub client_channel: u32,
    pub server_channel: u32,
    pub channel_type: String,
    pub initial_window_size: u32,
    pub maximum_packet_size: u32,
}

impl<'a> Channel<'a> {
    pub fn recv(&mut self) -> Result<Data> {
        self.client.recv()
    }

    pub fn send(&mut self, packet: &Data) -> Result<()> {
        self.client.send(packet)
    }

    pub fn client_setup(&mut self) -> Result<()> {
        if self.channel()? == message_code::SSH_MSG_GLOBAL_REQUEST {
            println!("");
        }

        if self.channel()? == message_code::SSH_MSG_DEBUG {
            println!("");
        }

        self.send_channel_open()?;

        if self.channel()? != message_code::SSH_MSG_CHANNEL_OPEN_CONFIRMATION {
            panic!("test")
        }

        Ok(())
    }

    pub fn channel(&mut self) -> Result<u8> {
        let mut payload = self.recv()?;
        let message_code: u8 = payload.get();
        match message_code {
            message_code::SSH_MSG_DEBUG => self.debug(&mut payload),
            message_code::SSH_MSG_GLOBAL_REQUEST => self.global_request(&mut payload),
            message_code::SSH_MSG_REQUEST_SUCCESS => {
                // self.recv_message_request_success(&mut payload)
            }
            message_code::SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
                self.channel_open_confirmation(&mut payload)?
            }
            message_code::SSH_MSG_REQUEST_FAILURE => {}
            message_code::SSH_MSG_CHANNEL_OPEN => self.message_channel_open(&mut payload),
            message_code::SSH_MSG_CHANNEL_OPEN_FAILURE => {
                self.message_channel_failure(&mut payload)
            }
            message_code::SSH_MSG_CHANNEL_WINDOW_ADJUST => {
                let recipient_channel: u32 = payload.get();
                let bytes_to_add: u32 = payload.get();
                println!("server channel: {}", recipient_channel);
                println!("window adjust: {}", bytes_to_add);
            }
            message_code::SSH_MSG_CHANNEL_DATA => {
                let recipient_channel: u32 = payload.get();
                let data: String = payload.get();
                println!("server channel: {}", recipient_channel);
                println!("{}", data);
            }
            message_code::SSH_MSG_CHANNEL_EXTENDED_DATA => {
                let recipient_channel: u32 = payload.get();
                let data_type_code: u32 = payload.get();
                let data: String = payload.get();
                println!("server channel: {}", recipient_channel);
                println!("data type: {}", data_type_code);
                println!("{}", data);
            }
            message_code::SSH_MSG_CHANNEL_EOF => {
                let recipient_channel: u32 = payload.get();
                println!("server channel: {}", recipient_channel);
            }
            message_code::SSH_MSG_CHANNEL_CLOSE => {
                let recipient_channel: u32 = payload.get();
                println!("server channel: {}", recipient_channel);
            }
            message_code::SSH_MSG_CHANNEL_REQUEST => self.message_channel_request(&mut payload),
            message_code::SSH_MSG_CHANNEL_SUCCESS => {
                let recipient_channel: u32 = payload.get();
                println!("server channel: {}", recipient_channel);
            }
            message_code::SSH_MSG_CHANNEL_FAILURE => {
                let recipient_channel: u32 = payload.get();
                println!("server channel: {}", recipient_channel);
            }
            _ => {
                panic!("unexpected message code")
            }
        }
        Ok(message_code)
    }
}

impl SshClient {
    pub fn pack_channel<'a>(&'a mut self) -> Channel<'a> {
        const BUF_SIZE: u32 = 0x8000;
        const LOCAL_WINDOW_SIZE: u32 = 0x200000;
        Channel {
            client: self,
            client_channel: 1,
            server_channel: 0,
            channel_type: "session".to_string(),
            initial_window_size: LOCAL_WINDOW_SIZE,
            maximum_packet_size: BUF_SIZE,
        }
    }
}
