use nom::AsBytes;

use super::error::{SshError, SshResult};
use crate::protocol::data::Data;
use crate::protocol::session::Session;

//   uint32    packet_length
//   byte      padding_length
//   byte[n1]  payload; n1 = packet_length - padding_length - 1 Initially, compression MUST be "none".
//   byte[n2]  random padding; n2 = padding_length
//   byte[m]   mac (Message Authentication Code - MAC); m = mac_length Initially, the MAC algorithm MUST be "none".
// mac = MAC(key, sequence_number || unencrypted_packet)
