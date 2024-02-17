use crate::protocol::{
    client::SshClient,
    data::{ByteString, Data},
    ssh2::message_code,
};
use anyhow::Result;

pub struct Channel<'a> {
    client: &'a mut SshClient,
    client_channel: u32,
    server_channel: u32,
    channel_type: String,
    initial_window_size: u32,
    maximum_packet_size: u32,
}

impl<'a> Channel<'a> {
    pub fn recv(&mut self) -> Result<Data> {
        self.client.recv()
    }

    pub fn send(&mut self, packet: &Data) -> Result<()> {
        self.client.send(packet)
    }

    pub fn client_setup(&mut self) -> Result<()> {
        self.channel()?;
        self.channel()?;
        self.send_channel_open()?;
        if self.channel()? != message_code::SSH_MSG_CHANNEL_OPEN_CONFIRMATION {
            panic!("test")
        }
        Ok(())
    }

    pub fn send_channel_open(&mut self) -> Result<()> {
        self.send(
            &Data::new()
                .put(&message_code::SSH_MSG_CHANNEL_OPEN)
                .put(&self.channel_type)
                .put(&self.client_channel)
                .put(&self.initial_window_size)
                .put(&self.maximum_packet_size),
        )
    }

    pub fn channel_open_confirmation(&mut self, payload: &mut Data) -> Result<()> {
        let recipient_channel: u32 = payload.get();
        let sender_channel: u32 = payload.get();
        let initial_window_size: u32 = payload.get();
        let maximum_packet_size: u32 = payload.get();
        println!(
            "{} {} {} {}",
            recipient_channel, sender_channel, initial_window_size, maximum_packet_size
        );
        match self.channel_type.as_str() {
            "session" => {}
            "x11" => {
                let originator_address: String = payload.get();
                let originator_port: u32 = payload.get();
                println!("{}:{}", originator_address, originator_port);
            }
            "forwarded-tcpip" => {
                let address: String = payload.get();
                let port: u32 = payload.get();
                let originator_address: String = payload.get();
                let originator_port: u32 = payload.get();
                println!("old: {}:{}", address, port);
                println!("new: {}:{}", originator_address, originator_port);
            }
            "direct-tcpip" => {
                let host: String = payload.get();
                let port: u32 = payload.get();
                let originator_address: String = payload.get();
                let originator_port: u32 = payload.get();
                println!("old: {}:{}", host, port);
                println!("new: {}:{}", originator_address, originator_port);
            }
            _ => {}
        }
        Ok(())
    }

    pub fn shell(&mut self) -> Result<()> {
        let env: String = "".to_string();
        let terminal_width_characters: u32 = 0;
        let terminal_height_rows: u32 = 0;
        let terminal_width_pixels: u32 = 0;
        let terminal_height_pixels: u32 = 0;
        let encoded_terminal_modes: ByteString = ByteString(vec![
            128, // TTY_OP_ISPEED
            0, 1, 0xc2, 0,   // 115200
            129, // TTY_OP_OSPEED
            0, 1, 0xc2, 0,    // 115200 again
            0_u8, // TTY_OP_END
        ]);
        let data = Data::new()
            .put(&message_code::SSH_MSG_CHANNEL_REQUEST)
            .put(&self.server_channel)
            .put(&"pty-req".to_string())
            .put(&false)
            .put(&env)
            .put(&terminal_width_characters)
            .put(&terminal_height_rows)
            .put(&terminal_width_pixels)
            .put(&terminal_height_pixels)
            .put(&encoded_terminal_modes);
        self.send(&data)?;

        let data = Data::new()
            .put(&message_code::SSH_MSG_CHANNEL_REQUEST)
            .put(&self.server_channel)
            .put(&"shell".to_string())
            .put(&true);
        self.send(&data)?;
        self.channel()?;
        self.channel()?;
        self.channel()?;
        self.channel()?;
        Ok(())
    }

    pub fn exec(&mut self, command: String) -> Result<()> {
        println!("exec: {}", command);
        let data = Data::new()
            .put(&message_code::SSH_MSG_CHANNEL_REQUEST)
            .put(&self.server_channel)
            .put(&"exec".to_string())
            .put(&true)
            .put(&command);
        self.send(&data)?;
        self.channel()?;
        self.channel()?;
        self.channel()?;
        self.channel()?;
        self.channel()?;
        self.channel()?;
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

    fn debug(&mut self, payload: &mut Data) {
        let want_reply: bool = payload.get();
        let debug: String = payload.get();
        println!("debug: {}", debug);
        println!("reply: {}", want_reply);
    }

    fn global_request(&mut self, payload: &mut Data) {
        let request_name: String = payload.get();
        let want_reply: bool = payload.get();
        println!("request: {}, reply: {}", request_name, want_reply);
        match request_name.as_str() {
            "tcpip-forward" => {
                let address: String = payload.get();
                let port: u32 = payload.get();
                println!("{}:{}", address, port);
            }
            "cancel-tcpip-forward" => {
                let address: String = payload.get();
                let port: u32 = payload.get();
                println!("{}:{}", address, port);
            }
            "hostkeys-00@openssh.com" => {
                // let blob: ByteString = payload.get();
            }
            _ => {}
        }
    }
    // fn recv_message_request_success(&mut self, payload: &mut Data) {
    //     pub const FILE_CHUNK: usize = 30000;
    //     let port: u32 = payload.get();
    //     data.put_u8(ssh_msg_code::SSH_MSG_CHANNEL_REQUEST)
    //         .put_u32(self.server_channel_no)
    //         .put_str(ssh_str::PTY_REQ)
    //         .put_u8(false as u8)
    //         .put_str(ssh_str::XTERM_VAR)
    //         .put_u32(tvs.0)
    //         .put_u32(tvs.1)
    //         .put_u32(tvs.2)
    //         .put_u32(tvs.3);
    //     let model = [
    //         128, // TTY_OP_ISPEED
    //         0, 1, 0xc2, 0,   // 115200
    //         129, // TTY_OP_OSPEED
    //         0, 1, 0xc2, 0,    // 115200 again
    //         0_u8, // TTY_OP_END
    //     ];
    //     data.put_u8s(&model);
    //     let mut data = Data::new();
    //     data.put(&message_code::SSH_MSG_CHANNEL_REQUEST)
    //         .put(self.server_channel_no)
    //         .put("shell".to_string())
    //         .put(false);
    //     self.send(data)
    // }
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
