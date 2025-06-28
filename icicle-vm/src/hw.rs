use std::any::Any;

use icicle_cpu::{
    mem::{IoMemory, MemError, MemResult},
    utils,
};

pub struct RngMem {
    limit: Option<usize>,
    rng: utils::XorShiftRng,
}

impl RngMem {
    pub fn new(seed: u64) -> Self {
        Self { rng: utils::XorShiftRng::new(seed), limit: None }
    }

    pub fn new_with_limit(seed: u64, limit: Option<usize>) -> Self {
        Self { rng: utils::XorShiftRng::new(seed), limit }
    }

    pub fn set_seed(&mut self, seed: u64) {
        self.rng.seed = seed;
    }
}

impl IoMemory for RngMem {
    fn read(&mut self, _addr: u64, buf: &mut [u8]) -> MemResult<()> {
        if self.limit.map_or(false, |x| x < buf.len()) {
            return Err(MemError::ReadWatch);
        }

        self.rng.fill_bytes(buf);
        if let Some(limit) = self.limit.as_mut() {
            *limit -= buf.len();
        }

        Ok(())
    }

    fn write(&mut self, _addr: u64, _value: &[u8]) -> MemResult<()> {
        Ok(())
    }

    fn snapshot(&mut self) -> Box<dyn Any> {
        Box::new((self.rng, self.limit))
    }

    fn restore(&mut self, snapshot: &Box<dyn Any>) {
        let (rng, limit) = *snapshot.downcast_ref().unwrap();
        self.rng = rng;
        self.limit = limit;
    }
}

pub struct AsciiLogger<W> {
    writer: W,
}

impl<W> AsciiLogger<W> {
    pub fn new(writer: W) -> Self {
        Self { writer }
    }
}

impl<W: std::io::Write + 'static> IoMemory for AsciiLogger<W> {
    fn read(&mut self, _addr: u64, _buf: &mut [u8]) -> MemResult<()> {
        Ok(())
    }

    fn write(&mut self, _addr: u64, value: &[u8]) -> MemResult<()> {
        for byte in value {
            if byte.is_ascii() && (!byte.is_ascii_control() || byte.is_ascii_whitespace()) {
                if self.writer.write_all(&[*byte]).is_err() {
                    return Err(MemError::Unknown);
                }
            }
        }
        Ok(())
    }
}

// @fixme: better tracing support for peripheral outputs.
#[derive(Clone, Default)]
pub struct DebugOutput {
    data: Vec<u8>,
}

impl DebugOutput {
    pub fn write(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
        if self.data.contains(&b'\n') && self.data.is_ascii() {
            eprint!("{}", std::str::from_utf8(&self.data).unwrap());
            self.data.clear();
        }
        else if self.data.len() > 64 {
            eprint!("{}", icicle_cpu::utils::hex(&self.data));
            self.data.clear();
        }
    }
}
