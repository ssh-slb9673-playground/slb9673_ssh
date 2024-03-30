use super::data::ByteString;

pub mod channel;
pub mod message;

enum ChannelData {
    Debug,
    GlobalRequest {
        address: String,
        port: u32,
    },
    GlobalRequestCancel {
        address: String,
        port: u32,
    },
    GlobalRequestHostKeys {
        hostkey1: ByteString,
        hostkey2: ByteString,
        hostkey3: ByteString,
    },
}
