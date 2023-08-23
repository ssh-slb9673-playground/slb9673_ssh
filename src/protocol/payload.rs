pub trait Packet<'a> {
    fn pack(self, client: &'a mut Client) -> SecPacket<'a>;
    fn unpack(pkt: SecPacket) -> SshResult<Self>
    where
        Self: Sized;
}
