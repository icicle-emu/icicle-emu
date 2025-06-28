use std::{
    collections::{HashMap, HashSet},
    rc::Rc,
};

use crate::cpu::{
    mem::{IoMemory, MemError, MemResult},
    utils::get_u64,
};

use super::{
    config::{Mcu, Peripheral},
    env::InterruptEntry,
};

pub(super) struct Peripherals<T> {
    unknown_handler: T,

    state: State,
    mapper: Mapper,

    names: HashMap<u64, String>,
    seen_reads: HashSet<u64>,
    seen_writes: HashSet<u64>,

    interrupts: Rc<Vec<InterruptEntry>>,
    interrupt_enabled: HashMap<u64, Vec<usize>>,
}

impl<T: IoMemory> Peripherals<T> {
    pub fn new(unknown_handler: T, config: &Mcu, interrupts: Rc<Vec<InterruptEntry>>) -> Self {
        let mut interrupt_enabled: HashMap<u64, Vec<usize>> = HashMap::new();
        for (i, entry) in interrupts.iter().enumerate() {
            interrupt_enabled.entry(entry.enable_addr).or_default().push(i);
        }

        let mut mapper = Mapper::default();
        Mpy32::register(config, &mut mapper);

        for (name, handler) in &config.peripherals {
            let addr = match config.symbols.get(name) {
                Some(addr) => *addr,
                None => {
                    tracing::warn!("Unknown peripheral: {} (skipping)", name);
                    continue;
                }
            };
            match *handler {
                Peripheral::LogWrite => {
                    mapper.write.push((addr, |state, value| state.debug.write(value)));
                }
                Peripheral::Byte(value) => mapper.map_read_byte(addr, value),
                Peripheral::Word(value) => mapper.map_read_word(addr, value),
            }
        }

        Self {
            unknown_handler,
            state: State::default(),
            mapper,

            names: config.symbols.iter().map(|(key, value)| (*value, key.clone())).collect(),
            seen_reads: HashSet::new(),
            seen_writes: HashSet::new(),

            interrupts,
            interrupt_enabled,
        }
    }

    fn debug_read(&mut self, addr: u64, buf: &[u8]) {
        if true {
            return;
        }

        let name = self.names.get(&addr).map_or("", |x| x.as_str());
        if self.seen_reads.insert(addr) {
            tracing::debug!("new reg: read[{}@{:#04x}]: {:02x?}", name, addr, buf);
        }
        tracing::trace!(" read[{}@{:#04x}]: {:02x?}", name, addr, buf);
    }

    fn debug_write(&mut self, addr: u64, value: &[u8]) {
        if true {
            return;
        }

        let name = self.names.get(&addr).map_or("", |x| x.as_str());
        if self.seen_writes.insert(addr) {
            tracing::debug!("new reg: write[{}@{:#04x}]: {:02x?}", name, addr, value);
        }
        tracing::trace!("write[{}@{:#04x}]: {:02x?}", name, addr, value);
    }
}

impl<T: IoMemory + 'static> IoMemory for Peripherals<T> {
    fn read(&mut self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
        if buf.len() > 8 {
            return Err(MemError::Unaligned);
        }

        if let Some((_, handler)) = self.mapper.read.iter().find(|x| x.0 == addr) {
            match handler {
                ReadHandler::Byte(x) => copy_trunc(buf, &x.to_le_bytes()),
                ReadHandler::Word(x) => copy_trunc(buf, &x.to_le_bytes()),
                ReadHandler::Func(handler) => handler(&mut self.state, buf),
            }
            return Ok(());
        }

        self.unknown_handler.read(addr, buf)?;

        // If the read overlaps with register that is used for enabling interrupts -- make sure we
        // read the correct values of those bits.
        if let Some(entries) = self.interrupt_enabled.get(&addr) {
            let mut value = get_u64(buf);

            for &id in entries {
                let interrupt = &self.interrupts[id];
                value = (value & (!interrupt.enabled_mask))
                    | (interrupt.enabled_mask * interrupt.enabled.get() as u64);
            }

            buf.copy_from_slice(&value.to_le_bytes()[..buf.len()]);
        }

        self.debug_read(addr, buf);
        Ok(())
    }

    fn write(&mut self, addr: u64, value: &[u8]) -> MemResult<()> {
        if value.len() > 8 {
            return Err(MemError::Unaligned);
        }

        if let Some((_, handler)) = self.mapper.write.iter().find(|x| x.0 == addr) {
            handler(&mut self.state, value);
            return Ok(());
        }

        if let Some(entries) = self.interrupt_enabled.get(&addr) {
            let value = get_u64(value);
            // Check whether we are enabling or disabling an interrupt
            for &id in entries {
                let interrupt = &self.interrupts[id];
                let enabled = value & interrupt.enabled_mask != 0;

                let name = &interrupt.name;
                if interrupt.enabled.get() != enabled {
                    let transition =
                        if enabled { "disabled -> enabled" } else { "enabled -> disabled" };
                    tracing::trace!("[{}]: {}", name, transition);
                }

                interrupt.enabled.set(enabled);
            }
        }
        else {
            self.unknown_handler.write(addr, value)?;
        }

        self.debug_write(addr, value);
        Ok(())
    }

    fn snapshot(&mut self) -> Box<dyn std::any::Any> {
        Box::new((self.state.clone(), self.unknown_handler.snapshot()))
    }

    fn restore(&mut self, snapshot: &Box<dyn std::any::Any>) {
        let (state, unknown_handler) = snapshot.downcast_ref::<(State, _)>().unwrap();
        self.state = state.clone();
        self.unknown_handler.restore(unknown_handler)
    }
}

enum ReadHandler {
    Byte(u8),
    Word(u16),
    Func(fn(&mut State, value: &mut [u8])),
}

type ReadMapper = Vec<(u64, ReadHandler)>;
type WriteMapper = Vec<(u64, fn(&mut State, value: &[u8]))>;

#[derive(Default)]
struct Mapper {
    read: ReadMapper,
    write: WriteMapper,
}

impl Mapper {
    fn map_read_byte(&mut self, addr: u64, value: u8) {
        self.read.push((addr, ReadHandler::Byte(value)));
    }

    fn map_read_word(&mut self, addr: u64, value: u16) {
        self.read.push((addr, ReadHandler::Word(value)));
        self.read.push((addr + 1, ReadHandler::Byte((value >> 8) as u8)));
    }
}

#[derive(Clone, Default)]
struct State {
    mpy32: Mpy32,
    debug: crate::hw::DebugOutput,
}

#[derive(Clone, Copy, Debug, Default)]
struct Mpy32 {
    mpy: [u8; 4],
    op2: [u8; 4],
}

impl Mpy32 {
    fn register(config: &Mcu, mapper: &mut Mapper) {
        if let Some(addr) = config.symbols.get("MPY") {
            mapper.write.push((*addr, |state, value| state.mpy32.write_mpy(value)));
        }
        if let Some(addr) = config.symbols.get("OP2") {
            mapper.write.push((*addr, |state, value| state.mpy32.write_op2(value)));
        }
        if let Some(addr) = config.symbols.get("RESLO") {
            mapper.read.push((*addr, ReadHandler::Func(|state, out| state.mpy32.read_reslo(out))));
        }
    }

    fn write_mpy(&mut self, value: &[u8]) {
        copy_trunc(&mut self.mpy, value);
    }

    fn write_op2(&mut self, value: &[u8]) {
        copy_trunc(&mut self.op2, value);
    }

    fn read_reslo(&self, out: &mut [u8]) {
        let value = u32::from_le_bytes(self.mpy).wrapping_mul(u32::from_le_bytes(self.op2)) as u16;
        copy_trunc(out, &value.to_le_bytes());
    }
}

#[inline]
fn copy_trunc(dst: &mut [u8], src: &[u8]) {
    let len = dst.len().min(src.len());
    dst[..len].copy_from_slice(&src[..len]);
}
