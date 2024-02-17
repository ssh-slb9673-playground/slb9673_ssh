use crate::protocol::channel::channel::Channel;
use crate::protocol::data::Data;

impl<'a> Channel<'a> {
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
                assert!(want_reply == false);
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
                assert!(want_reply == false);
                let client_can_do: bool = payload.get();
                println!("{}", client_can_do);
            }
            "signal" => {
                assert!(want_reply == false);
                let signal_name: String = payload.get();
                println!("signal: {}", signal_name);
            }
            "exit-status" => {
                // assert!(want_reply == false);
                let exit_status: u32 = payload.get();
                println!("exit: {}", exit_status);
            }
            "exit-signal" => {
                assert!(want_reply == false);
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
    // fn recv_(&mut self, payload: &mut Data) {}
    // fn recv_(&mut self, payload: &mut Data) {}
}
