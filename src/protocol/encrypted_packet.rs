struct EncryptedPacket {
    packet_length: Vec<u8>,
    encrypted_packet: Vec<u8>,
    mac: Vec<u8>,
}
