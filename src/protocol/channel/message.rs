use crate::protocol::channel::channel::Channel;
use crate::protocol::data::{ByteString, Data};
use crate::protocol::ssh2::message_code;

impl<'a> Channel<'a> {
    pub fn debug(&mut self, payload: &mut Data) {
        let want_reply: bool = payload.get();
        let debug: String = payload.get();
        println!("debug: {}", debug);
        println!("reply: {}", want_reply);
    }

    pub fn global_request(&mut self, payload: &mut Data) {
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
                // inform all keys
                let hostkey: ByteString = payload.get();
                let hostkey: ByteString = payload.get();
                let hostkey: ByteString = payload.get();
            }
            _ => {}
        }
    }

    pub fn channel_open_confirmation(&mut self, payload: &mut Data) -> anyhow::Result<()> {
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

    pub fn send_channel_open(&mut self) -> anyhow::Result<()> {
        self.send(
            &Data::new()
                .put(&message_code::SSH_MSG_CHANNEL_OPEN)
                .put(&self.channel_type)
                .put(&self.client_channel)
                .put(&self.initial_window_size)
                .put(&self.maximum_packet_size),
        )
    }

    pub fn send_channel_success(&mut self) -> anyhow::Result<()> {
        self.send(
            &Data::new()
                .put(&message_code::SSH_MSG_CHANNEL_SUCCESS)
                .put(&self.client_channel),
        )
    }

    pub fn message_channel_open(&mut self, payload: &mut Data) {
        let channel_type: String = payload.get();
        let sender_channel: u32 = payload.get();
        let initial_window_size: u32 = payload.get();
        let maximum_packet_size: u32 = payload.get();
        println!("client channel num: {}", sender_channel);
        println!("initial window size: {}", initial_window_size);
        println!("maximum packet size: {}", maximum_packet_size);
        match channel_type.as_str() {
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
    }

    pub fn message_channel_failure(&mut self, payload: &mut Data) {
        let recipient_channel: u32 = payload.get();
        let reason_code: u32 = payload.get();
        let description: String = payload.get();
        let language_tag: String = payload.get();
        println!("server channel: {}", recipient_channel);
        println!("{} {} {}", reason_code, description, language_tag);
    }

    pub fn message_channel_request(&mut self, payload: &mut Data) {
        let recipient_channel: u32 = payload.get();
        let request_type: String = payload.get();
        let want_reply: bool = payload.get();
        println!("server channel: {}", recipient_channel);
        println!("request type: {}", request_type);
        println!("want_reply: {}", want_reply);
        match request_type.as_str() {
            "pty-req" => {
                let env: String = payload.get();
                let terminal_width_characters: u32 = payload.get();
                let terminal_height_rows: u32 = payload.get();
                let terminal_width_pixels: u32 = payload.get();
                let terminal_height_pixels: u32 = payload.get();
                let encoded_terminal_modes: String = payload.get();
                println!("env: {}", env);
                println!(
                    "terminal: ({}, {}, {}, {})",
                    terminal_width_characters,
                    terminal_height_rows,
                    terminal_width_pixels,
                    terminal_height_pixels
                );
                println!("terminal mode: {}", encoded_terminal_modes);
            }
            "x11-req" => {
                let single_connection: bool = payload.get();
                let x11_authentication_protocol: String = payload.get();
                let x11_authentication_cookie: String = payload.get();
                let x11_screen_number: u32 = payload.get();
                println!(
                    "{} {} {} {}",
                    single_connection,
                    x11_authentication_protocol,
                    x11_authentication_cookie,
                    x11_screen_number
                );
            }
            "env" => {
                let variable_name: String = payload.get();
                let variable_value: String = payload.get();
                println!("env: {} = {}", variable_name, variable_value);
            }
            "shell" => {}
            "command" => {
                let command: String = payload.get();
                println!("command: {}", command);
            }
            "subsystem" => {
                let subsystem_name: String = payload.get();
                println!("subsystem: {}", subsystem_name);
            }
            "window-change" => {
                assert!(!want_reply);
                let terminal_width_columns: u32 = payload.get();
                let terminal_height_rows: u32 = payload.get();
                let terminal_width_pixels: u32 = payload.get();
                let terminal_height_pixels: u32 = payload.get();
                println!(
                    "terminal: ({}, {}, {}, {})",
                    terminal_width_columns,
                    terminal_height_rows,
                    terminal_width_pixels,
                    terminal_height_pixels
                );
            }
            "xon-xoff" => {
                assert!(!want_reply);
                let client_can_do: bool = payload.get();
                println!("{}", client_can_do);
            }
            "signal" => {
                assert!(!want_reply);
                let signal_name: String = payload.get();
                println!("signal: {}", signal_name);
            }
            "exit-status" => {
                // assert!(want_reply == false);
                let exit_status: u32 = payload.get();
                println!("exit: {}", exit_status);
            }
            "exit-signal" => {
                assert!(!want_reply);
                let signal_name: String = payload.get();
                let core_dumped: bool = payload.get();
                let error_message: String = payload.get();
                let language_tag: String = payload.get();
                println!("{} {} {}", signal_name, error_message, language_tag);
                if core_dumped {
                    println!("core dumped");
                }
            }
            _ => {}
        }
    }

    pub fn shell(&mut self) -> anyhow::Result<()> {
        let env: String = "".to_string();
        let (columns, rows) = termion::terminal_size()?;
        let (width, height) = termion::terminal_size_pixels()?;
        let terminal_width_characters: u32 = columns as u32;
        let terminal_height_rows: u32 = rows as u32;
        let terminal_width_pixels: u32 = width as u32;
        let terminal_height_pixels: u32 = height as u32;
        let encoded_terminal_modes: ByteString = ByteString(vec![
            128, // TTY_OP_ISPEED
            0, 1, 0xc2, 0,   // 115200
            129, // TTY_OP_OSPEED
            0, 1, 0xc2, 0,    // 115200 again
            0_u8, // TTY_OP_END
        ]);
        let mut data = Data::new();
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

        let (code, mut payload) = self.recv()?;
        self.furiwake(code, &mut payload)?;
        let (code, mut payload) = self.recv()?;
        self.furiwake(code, &mut payload)?;
        let (code, mut payload) = self.recv()?;
        self.furiwake(code, &mut payload)?;
        let (code, mut payload) = self.recv()?;
        self.furiwake(code, &mut payload)?;
        let (code, mut payload) = self.recv()?;
        self.furiwake(code, &mut payload)?;
        let (code, mut payload) = self.recv()?;
        self.furiwake(code, &mut payload)?;
        let (code, mut payload) = self.recv()?;
        self.furiwake(code, &mut payload)?;
        let (code, mut payload) = self.recv()?;
        self.furiwake(code, &mut payload)?;
        let (code, mut payload) = self.recv()?;
        self.furiwake(code, &mut payload)?;

        Ok(())
    }

    pub fn exec(&mut self, command: String) -> anyhow::Result<()> {
        println!("exec: {}", command);
        let mut data = Data::new();
        data.put(&message_code::SSH_MSG_CHANNEL_REQUEST)
            .put(&self.server_channel)
            .put(&"exec".to_string())
            .put(&true)
            .put(&command);
        self.send(&data)?;

        let (code, mut payload) = self.recv()?;
        match code {
            message_code::SSH_MSG_CHANNEL_WINDOW_ADJUST => self.furiwake(code, &mut payload)?,
            _ => unimplemented!(),
        }

        let (code, mut payload) = self.recv()?;
        match code {
            message_code::SSH_MSG_CHANNEL_SUCCESS => self.furiwake(code, &mut payload)?,
            _ => unimplemented!(),
        }

        loop {
            let (code, mut payload) = self.recv()?;
            match code {
                message_code::SSH_MSG_CHANNEL_DATA => self.furiwake(code, &mut payload)?,
                message_code::SSH_MSG_CHANNEL_EOF => break,
                _ => unimplemented!(),
            }
        }
        let (code, mut payload) = self.recv()?;
        match code {
            message_code::SSH_MSG_CHANNEL_REQUEST => self.furiwake(code, &mut payload)?,
            _ => unimplemented!(),
        }
        let (code, mut payload) = self.recv()?;
        match code {
            message_code::SSH_MSG_CHANNEL_REQUEST => self.furiwake(code, &mut payload)?,
            _ => unimplemented!(),
        }
        self.client_channel += 1;
        self.send_channel_open()?;

        let (code, mut payload) = self.recv()?;
        self.furiwake(code, &mut payload)?;
        let (code, mut payload) = self.recv()?;
        self.furiwake(code, &mut payload)?;
        let (code, mut payload) = self.recv()?;
        self.furiwake(code, &mut payload)?;

        Ok(())
    }

    // fn message_request_success(&mut self, payload: &mut Data) {
    //     pub const FILE_CHUNK: usize = 30000;
    //     let port: u32 = payload.get();
    //     let data = Data::new()
    //         .put(message_code::SSH_MSG_CHANNEL_REQUEST)
    //         .put(self.server_channel_no)
    //         .put(ssh_str::PTY_REQ)
    //         .put(false as u8)
    //         .put(ssh_str::XTERM_VAR)
    //         .put(tvs.0)
    //         .put(tvs.1)
    //         .put(tvs.2)
    //         .put(tvs.3);
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
