use std::net::SocketAddr;

use crate::protocol::{
    client::SshClient, data::ByteString, error::SshResult, session::Session, ssh2::message_code,
};

pub struct Channel {
    client: SshClient,
    address: SocketAddr,
    sender_channel: u32,
    recipient_channel: u32,
    want_reply: Option<u32>,
    initial_window_size: u32,
    maximum_packet_size: u32,
}

impl SshClient {
    pub fn channel(&mut self, session: &mut Session) -> SshResult<()> {
        let mut payload = self.recv()?.pack(session).unseal()?;
        let message_code: u8 = payload.get();
        match message_code {
            message_code::SSH_MSG_GLOBAL_REQUEST => {
                let request_name: String = payload.get();
                let want_reply: bool = payload.get();
                match request_name.as_str() {
                    "tcpip-forward" => {
                        let address: String = payload.get();
                        let port_number: u32 = payload.get();
                    }
                    "cancel-tcpip-forward" => {
                        let address: String = payload.get();
                        let port_number: u32 = payload.get();
                    }
                    _ => {}
                }
            }
            message_code::SSH_MSG_REQUEST_SUCCESS => {
                let port: u32 = payload.get();
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
                let data: ByteString = payload.get();
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
                        assert!(want_reply == false);
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
}
