#[repr(C)]
pub struct PacketEvent {
    pub len: u32,
    pub data: [u8; 0],
}

pub const MAX_PAYLOAD_LEN: usize = 256;
