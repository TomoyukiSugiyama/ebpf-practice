use aya::maps::ring_buf::RingBufItem;

#[repr(C)]
pub struct PacketEvent {
    pub len: u32,
    pub data: [u8; 0],
}

impl PacketEvent {
    pub fn from_bytes(bytes: &[u8]) -> Option<&Self> {
        if bytes.len() < core::mem::size_of::<PacketEvent>() {
            return None;
        }
        let header = unsafe { &*(bytes.as_ptr() as *const PacketEvent) };
        Some(header)
    }

    pub fn payload<'a>(&'a self) -> &'a [u8] {
        let data_ptr = unsafe { (self as *const PacketEvent).add(1) } as *const u8;
        unsafe { core::slice::from_raw_parts(data_ptr, self.len as usize) }
    }
}

pub trait PacketEventExt {
    fn packet_event(&self) -> Option<&PacketEvent>;
}

impl PacketEventExt for RingBufItem<'_> {
    fn packet_event(&self) -> Option<&PacketEvent> {
        PacketEvent::from_bytes(self)
    }
}
