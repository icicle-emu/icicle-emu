#![allow(unused)]

use std::{
    convert::TryInto,
    io::{self, Read, Write},
};

use anyhow::Context;

use crate::{shared_mem, FuzzConfig};

/// File descriptor used for receiving commands from the forkserver.
pub const RX_FD: usize = 198;

/// File descriptor used for sending commands to the forkserver.
pub const TX_FD: usize = RX_FD + 1;

/// Reporting errors
pub const OPT_ERROR: u32 = 0xf800008f;
fn get_opt_error(x: u32) -> u32 {
    (x & 0x00ffff00) >> 8
}
fn set_opt_error(x: u32) -> u32 {
    (x & 0x0000ffff) << 8
}

pub const ERROR_MAP_SIZE: u32 = 1;
pub const ERROR_MAP_ADDR: u32 = 2;
pub const ERROR_SHM_OPEN: u32 = 4;
pub const ERROR_SHMAT: u32 = 8;
pub const ERROR_MMAP: u32 = 16;

// Reporting options
pub const OPT_ENABLED: u32 = 0x80000001;
pub const OPT_MAPSIZE: u32 = 0x40000000;
pub const OPT_SNAPSHOT: u32 = 0x20000000;
pub const OPT_AUTODICT: u32 = 0x10000000;
pub const OPT_SHDMEM_FUZZ: u32 = 0x01000000;
pub const OPT_OLD_AFLPP_WORKAROUND: u32 = 0x0f000000;
pub const OPT_NEWCMPLOG: u32 = 0x02000000;

// FS_OPT_MAX_MAPSIZE is 8388608 = 0x800000 = 2^23 = 1 << 22
pub const OPT_MAX_MAPSIZE: u32 = (0x00fffffe >> 1) + 1;
pub fn get_opt_map_size(x: u32) -> u32 {
    ((x & 0x00fffffe) >> 1) + 1
}
pub fn set_opt_map_size(x: u32) -> u32 {
    if x <= 1 || x > OPT_MAX_MAPSIZE { 0 } else { (x - 1) << 1 }
}

pub struct Comms {
    rx: std::fs::File,
    tx: std::fs::File,
    killable_process: u32,
}

impl Comms {
    /// Safety: This function must not be called more than once.
    #[cfg(unix)]
    pub unsafe fn open() -> Self {
        use std::os::unix::io::FromRawFd;

        Self {
            rx: std::fs::File::from_raw_fd(RX_FD.try_into().unwrap()),
            tx: std::fs::File::from_raw_fd(TX_FD.try_into().unwrap()),
            killable_process: u32::MAX,
        }
    }

    #[cfg(not(unix))]
    pub unsafe fn open() -> Self {
        unimplemented!("");
    }

    /// Set status to the parent
    pub fn write(&mut self, status: u32) -> io::Result<()> {
        self.tx.write_all(&status.to_le_bytes())?;
        Ok(())
    }

    /// Read status response from parent
    pub fn read(&mut self) -> io::Result<u32> {
        let mut buf = [0; 4];
        self.rx.read_exact(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Check whether AFL is still alive
    pub fn is_alive(&mut self) -> bool {
        self.read().is_ok()
    }

    /// Send configuration information to AFL and check that AFL responds correctly.
    pub fn setup(&mut self, config: &FuzzConfig) -> anyhow::Result<()> {
        let mut status = OPT_ENABLED;
        status |= set_opt_map_size(shared_mem::MAP_SIZE as u32) | OPT_MAPSIZE;

        if config.shared_mem_inputs {
            status |= OPT_SHDMEM_FUZZ
        }

        status |= OPT_NEWCMPLOG;

        self.write(status).context("failed to send status to AFL")?;

        if config.shared_mem_inputs {
            // If we are running in shared memory mode, AFL will send a response back indicating
            // that it understood.
            let response = self.read().context("failed to get status response")?;
            let expected = OPT_SHDMEM_FUZZ | OPT_ENABLED;
            anyhow::ensure!(
                response == expected,
                "Unexpected response from AFL++ during forkserver setup: {response:#x} (expected: {expected:#x})",
            );
        }

        Ok(())
    }

    /// Notifies AFL that we are starting the next execution of the next fuzz case.
    pub fn start_fuzz_case(
        &mut self,
        interrupt_flag: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> anyhow::Result<()> {
        if interrupt_flag.swap(false, std::sync::atomic::Ordering::AcqRel)
            || self.killable_process == u32::MAX
        {
            self.killable_process = crate::spawn_killable_process(interrupt_flag.clone());
        }
        self.write(self.killable_process).context("failed to send fuzzer PID to AFL")?;
        Ok(())
    }
}

/// Safety: `ptr` must reference a region of memory with at least 64-bit alignment and where
/// the first 32-bits correspond to the length of the region, and be valid for a static lifetime
pub unsafe fn input_from_ptr(ptr: *mut u8) -> &'static [u8] {
    use crate::is_cmplog_server;
    use std::convert::TryInto;

    let len = u32::from_le_bytes(std::ptr::read(ptr as *const [u8; std::mem::size_of::<u32>()]));
    let slice = std::slice::from_raw_parts_mut(
        ptr.add(std::mem::size_of::<u32>()),
        len.try_into().unwrap(),
    );

    if is_cmplog_server() {
        tracing::debug!(target: "cmplog_input", "len={:>3}, bytes={}", len, BytesDisplay(slice));
    }
    else {
        tracing::debug!(target: "tracer_input", "len={:>3}, bytes={}", len, BytesDisplay(slice));
    }

    slice
}

struct BytesDisplay<'a>(&'a [u8]);

impl<'a> std::fmt::Display for BytesDisplay<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use bstr::ByteSlice;

        match self.0.len() < 65 {
            true => write!(f, "{:?}", self.0.as_bstr()),
            false => write!(f, "{:?}...", self.0[..65].as_bstr()),
        }
    }
}
