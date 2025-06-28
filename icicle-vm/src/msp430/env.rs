use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

use crate::{
    cpu::{
        debug_info::DebugInfo,
        elf::ElfLoader,
        mem::{perm, IoMemory, IoMemoryAny, Mapping, MemError, MemResult},
        utils::XorShiftRng,
        Cpu, Environment, Exception, ExceptionCode, ValueSource,
    },
    hw, BuildError, VmExit,
};

use super::config::{self, Config, Mcu};

/// The bit in the status register representing whether interrupts are currently enabled.
const GIE_BIT: u32 = 0b0000_1000;

/// The bit in the status register representing whether the CPU is off.
const CPUOFF_BIT: u32 = 0b0001_0000;

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
struct CpuFlags {
    /// Whether the CPUOFF flag is set.
    cpu_off: bool,

    /// Whether the GIE (global interrupt enable) flag is set.
    interrupts_enabled: bool,
}

impl CpuFlags {
    fn from_status_reg(value: u32) -> Self {
        Self { cpu_off: value & CPUOFF_BIT != 0, interrupts_enabled: value & GIE_BIT != 0 }
    }
}

pub struct Msp430 {
    /// The function that is called on unknown peripherals.
    pub unknown_peripheral_handler: UnknownPeripheralHandler,

    /// A rng to determine which interrupt will get triggered next.
    pub interrupt_rng: XorShiftRng,

    /// Debug info from the loaded binary.
    pub debug_info: DebugInfo,

    /// The varnode that stores afl_prev_pc (if available).
    pub afl_prev_pc: Option<pcode::VarNode>,

    /// Interrupts configured for the current microcontroller.
    interrupts: Rc<Vec<InterruptEntry>>,

    /// The varnode that stores the stack stack
    sp: pcode::VarNode,

    /// The varnode that stores the status register.
    sr: pcode::VarNode,

    /// The rate at which we should schedule interrupts at.
    interrupt_interval: u64,

    /// The icount to trigger the next interrupt at.
    next_interrupt: u64,

    /// MCU configuration for the processor
    mcu: Mcu,

    /// Enable writing log data to stdout.
    log_stdout: bool,

    /// The address we should load raw binaries at.
    load_addr: u64,

    /// The current CPU flags.
    flags: CpuFlags,

    interrupt: Option<Interrupt>,
}

#[derive(Copy, Clone)]
struct Interrupt {
    /// The PC value we entered the interrupt from.
    return_addr: u64,
    /// The (block id, offset) that we entered the interrupt from.
    return_block: (u64, u64),
    /// The value of `afl_prev_pc` when we entered the interrupt.
    afl_prev_pc: u16,
}

const INTERRUPT_RET_PC: u32 = 0xfff0;

impl Msp430 {
    pub fn new(cpu: &Cpu, config: Config) -> Result<Self, BuildError> {
        let mcu = Mcu::from_path(&config.mcu)
            .map_err(|e| BuildError::FailedToInitEnvironment(e.to_string()))?;
        Ok(Self {
            interrupts: Rc::new(interrupts(&mcu)),
            interrupt_rng: XorShiftRng::new(0x1234),
            sp: cpu.arch.sleigh.get_reg("SP").unwrap().var,
            sr: cpu.arch.sleigh.get_reg("SR").unwrap().var,
            afl_prev_pc: None,
            interrupt_interval: config.interrupt_interval,
            next_interrupt: config.interrupt_interval,
            debug_info: DebugInfo::default(),
            unknown_peripheral_handler: UnknownPeripheralHandler::new(hw::RngMem::new_with_limit(
                config.rng_seed,
                config.rng_limit,
            )),
            mcu,
            log_stdout: config.log_stdout,
            load_addr: config.load_addr,
            flags: CpuFlags::default(),
            interrupt: None,
        })
    }

    fn call_interrupt(&mut self, cpu: &mut Cpu, isr_addr: u64) -> MemResult<()> {
        if self.interrupt.is_some() {
            // Avoid nested interrupts (for now)
            return Ok(());
        }

        let sp: u32 = cpu.read_var(self.sp);
        if sp < 4 {
            return Err(MemError::Unmapped);
        }

        let pc: u32 = cpu.read_pc() as u32;
        let sr: u32 = cpu.read_var(self.sr);

        let block = cpu.block_id;
        let offset = cpu.block_offset;
        tracing::trace!(
            "[{}] Interrupt@{isr_addr:#x} (pc={pc:#x}, sp={sp:#x}, block={block}, offset={offset})",
            cpu.icount,
        );

        let afl_prev_pc = match self.afl_prev_pc {
            Some(reg) => {
                let prev = cpu.read_var(reg);
                cpu.write_var::<u16>(reg, 0);
                prev
            }
            None => 0,
        };
        self.interrupt =
            Some(Interrupt { return_addr: pc as u64, return_block: (block, offset), afl_prev_pc });

        // Save SR on to the stack, and magic interrupt value on the stack.
        cpu.mem.write_u16((sp - 2) as u64, INTERRUPT_RET_PC as u16, perm::WRITE)?;
        let packed = sr & 0xfff | (INTERRUPT_RET_PC >> 4) & 0xf000;
        cpu.mem.write_u16((sp - 4) as u64, packed as u16, perm::WRITE)?;

        // Ensure CPUOFF bit is cleared
        cpu.write_var(self.sr, sr & !CPUOFF_BIT);
        self.flags.cpu_off = false;

        // Update stack pointer and jump to ISR handler.
        cpu.write_var(self.sp, sp - 4);
        let isr = cpu.mem.read_u16(isr_addr, perm::READ)? as u32;
        cpu.exception = Exception::new(ExceptionCode::ExternalAddr, isr as u64);

        Ok(())
    }

    fn interrupt_return(&mut self, cpu: &mut Cpu, interrupt: Interrupt) {
        tracing::trace!("[{}] Return from interrupt", cpu.icount);

        cpu.write_pc(interrupt.return_addr);

        cpu.block_id = interrupt.return_block.0;
        cpu.block_offset = interrupt.return_block.1;

        if let Some(reg) = self.afl_prev_pc {
            cpu.write_var(reg, interrupt.afl_prev_pc);
        }

        cpu.exception.clear();
    }

    fn configure_mem(&mut self, cpu: &mut Cpu) {
        let peripheral_handler = cpu.mem.register_io_handler(crate::msp430::hw::Peripherals::new(
            self.unknown_peripheral_handler.clone(),
            &self.mcu,
            self.interrupts.clone(),
        ));

        let logger = match self.log_stdout {
            true => cpu.mem.register_io_handler(hw::AsciiLogger::new(std::io::stdout())),
            false => cpu.mem.register_io_handler(hw::AsciiLogger::new(std::io::sink())),
        };

        // Note: we sort the values here to avoid non-determinism. This non-determinism is caused by
        // the fact that `memset` operations can avoid allocating memory in some cases.
        //
        // @fixme: The mapping interval tree should not depend on the order memory is inserted in.
        let mut mappings: Vec<_> = self.mcu.memory_layout.values().collect();
        mappings.sort_by_key(|x| x.start);

        for entry in mappings {
            // We clear the 'execute' permission and expect that it will be when the binary is
            // loaded. This prevents the emulator from ever executing code that is not in the
            // binary.
            let perm = (entry.perm.value() | perm::MAP) & !perm::EXEC;
            let len = entry
                .end
                .checked_sub(entry.start)
                .expect("Memory mapping end address occurs before starting address");
            let result = match &entry.value {
                config::Value::None => {
                    cpu.mem.map_memory_len(entry.start, len, Mapping { perm, value: 0xff })
                }
                &config::Value::Fill(value) => cpu
                    .mem
                    .map_memory_len(entry.start, len, Mapping { perm: perm | perm::INIT, value }),
                config::Value::Bytes(bytes) => {
                    cpu.mem.map_memory_len(entry.start, len, Mapping {
                        perm: perm | perm::INIT,
                        value: 0,
                    });
                    cpu.mem.write_bytes(entry.start, bytes, perm::NONE).is_ok()
                }
                config::Value::Io => cpu.mem.map_memory_len(entry.start, len, peripheral_handler),
                config::Value::LogWrite => cpu.mem.map_memory_len(entry.start, len, logger),
            };

            if !result {
                // @todo: report this to the user instead of generating a panic.
                panic!("failed to map memory region: {:0x?}", entry);
            }
        }

        tracing::debug!("memory layout: {:#x?}", cpu.mem.get_mapping());
    }

    /// Update CPU flags returning whether they were changed or not.
    fn update_flags(&mut self, cpu: &mut Cpu) -> bool {
        let sr = cpu.read_var(self.sr);
        let new = CpuFlags::from_status_reg(sr);
        if self.flags == new {
            return false;
        }

        tracing::trace!(
            "[{:#0x},{}] CPUOFF={}->{}, GIE={}->{}, sr={sr:#0x}",
            cpu.read_pc(),
            cpu.icount,
            self.flags.cpu_off,
            new.cpu_off,
            self.flags.interrupts_enabled,
            new.interrupts_enabled
        );
        self.flags = new;
        true
    }

    fn trigger_next_interrupt(&mut self, cpu: &mut Cpu) -> bool {
        self.next_interrupt = cpu.icount + self.interrupt_interval;

        if !self.flags.interrupts_enabled || self.interrupt.is_some() {
            return false;
        }

        if self.interrupts.is_empty() {
            return false;
        }

        // Find the next interrupt to trigger
        // @fixme: this isn't a "fair" way to restrict the range
        let mut interrupt_index = self.interrupt_rng.next() as usize % self.interrupts.len();
        for _ in 0..self.interrupts.len() {
            if interrupt_index >= self.interrupts.len() {
                interrupt_index = 0;
            }

            let interrupt = &self.interrupts[interrupt_index];
            if interrupt.enabled.get() {
                tracing::trace!("[{}] {}: {}_ISR", cpu.icount, interrupt.name, interrupt.isr_name);
                let isr_addr = interrupt.isr;
                if let Err(e) = self.call_interrupt(cpu, isr_addr) {
                    cpu.exception =
                        Exception::new(ExceptionCode::from_load_error(e), cpu.read_pc());
                }
                return true;
            }

            interrupt_index += 1;
        }

        false
    }
}

impl ElfLoader for Msp430 {
    const DYNAMIC_MEMORY: bool = false;
    const LOAD_AT_PHYSICAL_ADDRESS: bool = true;
}

impl Environment for Msp430 {
    fn load(&mut self, cpu: &mut Cpu, path: &[u8]) -> Result<(), String> {
        self.configure_mem(cpu);

        // @todo: allow the loader to be configured.
        if path.ends_with(b"bin") {
            let data = self.read_file(path)?;
            let addr = self.load_addr;

            cpu.mem
                .write_bytes(addr, &data, perm::NONE)
                .map_err(|e| format!("Failed to write to memory at {addr:#0x}: {e}"))?;

            // @fixme: these permissions are not correct.
            let perm = perm::READ | perm::INIT | perm::EXEC | perm::MAP;

            cpu.mem
                .update_perm(addr, data.len() as u64, perm)
                .map_err(|e| format!("Failed to update permissions at {addr:#0x}: {e}"))?;
        }
        else if path.ends_with(b"hex") {
            let data = self.read_file(path)?;
            let input =
                std::str::from_utf8(&data).map_err(|e| format!("invalid ihex file: {e}"))?;

            let reader = ihex::Reader::new(input);
            let mut base_addr = 0x0;
            for entry in reader {
                match entry.map_err(|e| format!("invalid ihex file: {e}"))? {
                    ihex::Record::Data { offset, value } => {
                        let addr = base_addr + offset as u64;
                        cpu.mem
                            .write_bytes(addr, &value, perm::NONE)
                            .map_err(|e| format!("Failed to write to memory at {addr:#0x}: {e}"))?;
                        let perm = perm::READ | perm::INIT | perm::EXEC;
                        cpu.mem.update_perm(addr, value.len() as u64, perm).map_err(|e| {
                            format!("Failed to update permissions at {addr:#0x}: {e}")
                        })?;
                    }
                    ihex::Record::StartLinearAddress(addr) => base_addr = addr as u64,
                    ihex::Record::EndOfFile => break,
                    other => return Err(format!("Unsupported ihex record: {other:x?}")),
                }
            }
        }
        else {
            let metadata = self.load_elf(cpu, path)?;
            if metadata.interpreter.is_some() {
                return Err("Dynamically linked binaries are not supported for msp430-none".into());
            }
            if metadata.binary.offset != 0 {
                return Err("Expected no relocations for msp430-none".into());
            }
            self.debug_info = metadata.debug_info;
        }

        tracing::debug!("memory layout: {:#x?}", cpu.mem.get_mapping());

        // Reset vector contains the entry address
        let entry = cpu
            .mem
            .read_u16(0xfffe, perm::NONE)
            .map_err(|e| format!("Failed to read entrypoint: {e:?}"))? as u64;
        cpu.write_pc(entry);

        Ok(())
    }

    fn next_timer(&self) -> u64 {
        self.next_interrupt
    }

    fn handle_exception(&mut self, cpu: &mut Cpu) -> Option<crate::VmExit> {
        match ExceptionCode::from_u32(cpu.exception.code) {
            ExceptionCode::InstructionLimit => {
                // Check whether we want to trigger an interrupt.
                if self.next_interrupt <= cpu.icount {
                    if self.next_interrupt != cpu.icount {
                        tracing::warn!(
                            "[{}] Missed interrupt trigger point at {}",
                            cpu.icount,
                            self.next_interrupt,
                        );
                    }

                    if !self.trigger_next_interrupt(cpu) {
                        tracing::trace!("[{}] no interrupts to trigger", cpu.icount);
                    }
                }

                None
            }

            // Status register modified
            ExceptionCode::CpuStateChanged => {
                cpu.exception.clear();
                if self.update_flags(cpu) && self.flags.cpu_off {
                    // Immediately try to trigger the next interrupt if the cpu was turned off.
                    if !self.trigger_next_interrupt(cpu) {
                        tracing::error!(
                            "[{:#x}] Deadlock CPU is off but no interrupts active",
                            cpu.read_pc()
                        );
                        return Some(VmExit::Deadlock);
                    }
                }

                None
            }

            // Return from interrupt
            ExceptionCode::ShadowStackInvalid
            | ExceptionCode::InvalidTarget
            | ExceptionCode::InvalidInstruction
                if cpu.exception.value == 0xfff0 =>
            {
                if let Some(interrupt) = self.interrupt.take() {
                    self.interrupt_return(cpu, interrupt);
                }
                None
            }

            _ => None,
        }
    }

    fn snapshot(&mut self) -> Box<dyn std::any::Any> {
        let interrupt_enable_state: Vec<_> =
            self.interrupts.iter().map(|x| x.enabled.get()).collect();
        Box::new((
            self.interrupt_rng,
            interrupt_enable_state,
            self.flags,
            self.next_interrupt,
            self.interrupt,
        ))
    }

    fn restore(&mut self, snapshot: &Box<dyn std::any::Any>) {
        let (interrupt_rng, interrupt_enable_state, flags, next_interrupt, interrupt) = snapshot
            .downcast_ref::<(XorShiftRng, Vec<bool>, CpuFlags, u64, Option<Interrupt>)>()
            .unwrap();
        self.interrupt_rng = *interrupt_rng;

        for (interrupt, enabled) in self.interrupts.iter().zip(interrupt_enable_state) {
            interrupt.enabled.set(*enabled);
        }

        self.flags = *flags;
        self.next_interrupt = *next_interrupt;
        self.interrupt = *interrupt;
    }

    fn debug_info(&self) -> Option<&DebugInfo> {
        Some(&self.debug_info)
    }
}

#[derive(Clone)]
pub struct UnknownPeripheralHandler {
    pub inner: Rc<RefCell<Box<dyn IoMemoryAny>>>,
}

impl UnknownPeripheralHandler {
    pub fn new(inner: impl IoMemory + 'static) -> Self {
        Self { inner: Rc::new(RefCell::new(Box::new(inner))) }
    }
}

impl IoMemory for UnknownPeripheralHandler {
    fn read(&mut self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
        self.inner.borrow_mut().read(addr, buf)
    }

    fn write(&mut self, addr: u64, value: &[u8]) -> MemResult<()> {
        self.inner.borrow_mut().write(addr, value)
    }

    fn snapshot(&mut self) -> Box<dyn std::any::Any> {
        self.inner.borrow_mut().snapshot()
    }

    fn restore(&mut self, snapshot: &Box<dyn std::any::Any>) {
        self.inner.borrow_mut().restore(snapshot);
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct InterruptEntry {
    /// The name of the interrupt
    pub name: String,

    /// The address of the handler routine for this interrupt.
    pub isr: u64,

    /// The name of the handler routine for this interrupt.
    pub isr_name: String,

    /// The address of the register used to determine whether this interrupt is currently enabled.
    pub enable_addr: u64,

    /// The bits within `enable_addr` that control whether the interrupt is enabled.
    pub enabled_mask: u64,

    /// The address of the register to store interrupt flags.
    pub flag_addr: u64,

    /// The bits within `flag_addr` that indicate that an interrupt has been triggered.
    pub flag_mask: u64,

    /// Whether the interrupt is currently enabled.
    pub enabled: Cell<bool>,
}

fn interrupts(config: &config::Mcu) -> Vec<InterruptEntry> {
    let mut entries = vec![];
    for (name, entry) in &config.interrupts {
        entries.push(InterruptEntry {
            name: name.clone(),
            isr: config.symbols[&entry.isr],
            isr_name: entry.isr.clone(),
            enable_addr: config.symbols[&entry.enable.0],
            enabled_mask: entry.enable.1,
            flag_addr: config.symbols[&entry.flag.0],
            flag_mask: entry.flag.1,
            enabled: Cell::new(false),
        });
    }
    entries.sort_unstable_by_key(|x| (x.enable_addr, x.enabled_mask));
    entries
}
