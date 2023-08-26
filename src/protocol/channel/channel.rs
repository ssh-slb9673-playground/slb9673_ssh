use std::net::SocketAddr;

use crate::protocol::{
    client::SshClient,
    data::{ByteString, Data},
    error::SshResult,
    ssh2::message_code,
};

pub struct Channel<'a> {
    client: &'a mut SshClient,
    client_channel: u32,
    server_channel: u32,
    channel_type: String,
    want_reply: Option<u32>,
    initial_window_size: u32,
    maximum_packet_size: u32,
}

impl<'a> Channel<'a> {
    pub fn recv(&mut self) -> SshResult<Data> {
        self.client.recv()
    }

    pub fn send(&mut self, packet: &Data) -> SshResult<()> {
        self.client.send(packet)
    }

    pub fn client_setup(&mut self) -> SshResult<()> {
        self.send_channel_open()?;
        self.channel_open_confirmation()?;
        Ok(())
    }

    pub fn send_channel_open(&mut self) -> SshResult<()> {
        let mut data = Data::new();
        data.put(&message_code::SSH_MSG_CHANNEL_OPEN)
            .put(&self.channel_type)
            .put(&self.client_channel)
            .put(&self.initial_window_size)
            .put(&self.maximum_packet_size);
        self.send(&data)
    }

    pub fn channel_open_confirmation(&mut self) -> SshResult<()> {
        let mut payload = self.recv()?;
        let message_code: u8 = payload.get();
        match message_code {
            message_code::SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
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
                    }
                    "forwarded-tcpip" => {
                        let address: String = payload.get();
                        let old_port: u32 = payload.get();
                        let originator_ip_address: String = payload.get();
                        let originator_port: u32 = payload.get();
                    }
                    "direct-tcpip" => {
                        let host: String = payload.get();
                        let port: u32 = payload.get();
                        let originator_ip_address: String = payload.get();
                        let originator_port: u32 = payload.get();
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub fn shell(&mut self) -> SshResult<()> {
        let mut data = Data::new();
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
        data.put(&message_code::SSH_MSG_CHANNEL_REQUEST)
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

        let mut data = Data::new();
        data.put(&message_code::SSH_MSG_CHANNEL_REQUEST)
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

    pub fn exec(&mut self, command: String) -> SshResult<()> {
        println!("exec: {}", command);
        let mut data = Data::new();
        data.put(&message_code::SSH_MSG_CHANNEL_REQUEST)
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

    pub fn channel(&mut self) -> SshResult<()> {
        let mut payload = self.recv()?;
        let message_code: u8 = payload.get();
        match message_code {
            message_code::SSH_MSG_DEBUG => self.recv_debug(&mut payload),
            message_code::SSH_MSG_GLOBAL_REQUEST => self.recv_global_request(&mut payload),
            message_code::SSH_MSG_REQUEST_SUCCESS => {
                // self.recv_message_request_success(&mut payload)
            }
            message_code::SSH_MSG_REQUEST_FAILURE => {}
            message_code::SSH_MSG_CHANNEL_OPEN => {
                let channel_type: String = payload.get();
                let sender_channel: u32 = payload.get();
                let initial_window_size: u32 = payload.get();
                let maximum_packet_size: u32 = payload.get();
                match channel_type.as_str() {
                    "session" => {}
                    "x11" => {
                        let originator_address: String = payload.get();
                        let originator_port: u32 = payload.get();
                    }
                    "forwarded-tcpip" => {
                        let address: String = payload.get();
                        let old_port: u32 = payload.get();
                        let originator_ip_address: String = payload.get();
                        let originator_port: u32 = payload.get();
                    }
                    "direct-tcpip" => {
                        let host: String = payload.get();
                        let port: u32 = payload.get();
                        let originator_ip_address: String = payload.get();
                        let originator_port: u32 = payload.get();
                    }
                    _ => {}
                }
            }
            message_code::SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
                let recipient_channel: u32 = payload.get();
                let sender_channel: u32 = payload.get();
                let initial_window_size: u32 = payload.get();
                let maximum_packet_size: u32 = payload.get();
                match self.channel_type.as_str() {
                    "session" => {}
                    "x11" => {
                        let originator_address: String = payload.get();
                        let originator_port: u32 = payload.get();
                    }
                    "forwarded-tcpip" => {
                        let address: String = payload.get();
                        let old_port: u32 = payload.get();
                        let originator_ip_address: String = payload.get();
                        let originator_port: u32 = payload.get();
                    }
                    "direct-tcpip" => {
                        let host: String = payload.get();
                        let port: u32 = payload.get();
                        let originator_ip_address: String = payload.get();
                        let originator_port: u32 = payload.get();
                    }
                    _ => {}
                }
            }
            message_code::SSH_MSG_CHANNEL_OPEN_FAILURE => {
                let recipient_channel: u32 = payload.get();
                let reason_code: u32 = payload.get();
                let description: String = payload.get();
                let language_tag: String = payload.get();
            }
            message_code::SSH_MSG_CHANNEL_WINDOW_ADJUST => {
                let recipient_channel: u32 = payload.get();
                let bytes_to_add: u32 = payload.get();
            }
            message_code::SSH_MSG_CHANNEL_DATA => {
                let recipient_channel: u32 = payload.get();
                let data: String = payload.get();
                println!("{}", data);
            }
            message_code::SSH_MSG_CHANNEL_EXTENDED_DATA => {
                let recipient_channel: u32 = payload.get();
                let data_type_code: u32 = payload.get();
                let data: ByteString = payload.get();
            }
            message_code::SSH_MSG_CHANNEL_EOF => {
                let recipient_channel: u32 = payload.get();
            }
            message_code::SSH_MSG_CHANNEL_CLOSE => {
                let recipient_channel: u32 = payload.get();
            }
            message_code::SSH_MSG_CHANNEL_REQUEST => {
                let recipient_channel: u32 = payload.get();
                let request_type: String = payload.get();
                let want_reply: bool = payload.get();
                match request_type.as_str() {
                    "pty-req" => {
                        let env: String = payload.get();
                        let terminal_width_characters: u32 = payload.get();
                        let terminal_height_rows: u32 = payload.get();
                        let terminal_width_pixels: u32 = payload.get();
                        let terminal_height_pixels: u32 = payload.get();
                        let encoded_terminal_modes: String = payload.get();
                    }
                    "x11-req" => {
                        let single_connection: bool = payload.get();
                        let x11_authentication_protocol: String = payload.get();
                        let x11_authentication_cookie: String = payload.get();
                        let x11_screen_number: u32 = payload.get();
                    }
                    "env" => {
                        let variable_name: String = payload.get();
                        let variable_value: String = payload.get();
                    }
                    "shell" => {}
                    "command" => {
                        let command: String = payload.get();
                    }
                    "subsystem" => {
                        let subsystem_name: String = payload.get();
                    }
                    "window-change" => {
                        assert!(want_reply == false);
                        let terminal_width_columns: u32 = payload.get();
                        let terminal_height_rows: u32 = payload.get();
                        let terminal_width_pixels: u32 = payload.get();
                        let terminal_height_pixels: u32 = payload.get();
                    }
                    "xon-xoff" => {
                        assert!(want_reply == false);
                        let client_can_do: bool = payload.get();
                    }
                    "signal" => {
                        assert!(want_reply == false);
                        let signal_name: String = payload.get();
                    }
                    "exit-status" => {
                        // assert!(want_reply == false);
                        let exit_status: u32 = payload.get();
                    }
                    "exit-signal" => {
                        assert!(want_reply == false);
                        let signal_name: String = payload.get();
                        let core_dumped: bool = payload.get();
                        let error_message: String = payload.get();
                        let language_tag: String = payload.get();
                    }
                    _ => {}
                }
            }
            message_code::SSH_MSG_CHANNEL_SUCCESS => {
                let recipient_channel: u32 = payload.get();
            }
            message_code::SSH_MSG_CHANNEL_FAILURE => {
                let recipient_channel: u32 = payload.get();
            }
            _ => {
                panic!("unexpected message code")
            }
        }
        Ok(())
    }

    fn recv_debug(&mut self, payload: &mut Data) {
        let want_reply: bool = payload.get();
        let debug: String = payload.get();
        println!("debug: {}", debug);
    }

    fn recv_global_request(&mut self, payload: &mut Data) {
        let request_name: String = payload.get();
        let want_reply: bool = payload.get();
        println!("request: {}, reply: {}", request_name, want_reply);
        match request_name.as_str() {
            "tcpip-forward" => {
                let address: String = payload.get();
                let port_number: u32 = payload.get();
            }
            "cancel-tcpip-forward" => {
                let address: String = payload.get();
                let port_number: u32 = payload.get();
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

    // fn recv_(&mut self, payload: &mut Data) {}
    // fn recv_(&mut self, payload: &mut Data) {}
    // fn recv_(&mut self, payload: &mut Data) {}
    // fn recv_(&mut self, payload: &mut Data) {}
    // fn recv_(&mut self, payload: &mut Data) {}
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
            want_reply: None,
            initial_window_size: LOCAL_WINDOW_SIZE,
            maximum_packet_size: BUF_SIZE,
        }
    }
}
