use icicle_cpu::{ExceptionCode, VmExit};

include!(concat!(env!("OUT_DIR"), "/errno.rs"));

/// Error values between 0x10000 and 0x1ffff are reserved for custom vm exists
pub fn vm_exit(value: u64) -> Option<VmExit> {
    if value & 0x10000 == 0x10000 {
        return Some(VmExit::UnhandledException((ExceptionCode::Environment, value & 0xffff)));
    }
    None
}

pub const HOOKED: u64 = 0x10001;
