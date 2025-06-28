use std::collections::HashMap;

use anyhow::Context;
use crate::cpu::mem::perm;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Config {
    #[serde(default)]
    pub load_addr: u64,
    pub interrupt_interval: u64,
    pub mcu: String,
    #[serde(default)]
    pub rng_limit: Option<usize>,
    #[serde(default = "default_true")]
    pub log_stdout: bool,
    #[serde(default = "default_initial_seed")]
    pub rng_seed: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            load_addr: 0x0000,
            interrupt_interval: 0x8_0000,
            mcu: "msp430f2132".into(),
            rng_limit: None,
            log_stdout: true,
            rng_seed: 0x1234,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_initial_seed() -> u64 {
    0x1234
}

#[derive(serde::Deserialize)]
pub struct Mcu {
    pub memory_layout: HashMap<String, Memory>,
    #[serde(default)]
    pub interrupts: HashMap<String, Interrupt>,
    #[serde(default)]
    pub symbols: HashMap<String, u64>,
    #[serde(default)]
    pub peripherals: HashMap<String, Peripheral>,
}

impl Mcu {
    pub fn from_path(mcu: &str) -> anyhow::Result<Self> {
        // Check for configuration either relative to working directory, or relative to executable
        // directory.
        let input = match std::fs::read(mcu) {
            Ok(data) => data,
            Err(e) => {
                let read_from_exe_path = || {
                    let exe = std::env::current_exe().ok()?;
                    std::fs::read(exe.parent()?.join(mcu)).ok()
                };
                match read_from_exe_path() {
                    Some(data) => data,
                    None => anyhow::bail!("Failed to find {mcu}: {e}"),
                }
            }
        };
        ron::de::from_bytes(&input).with_context(|| format!("error deserializing: {mcu}"))
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct Memory {
    /// The stating address of the memory region.
    pub start: u64,

    /// The ending address of the memory region.
    pub end: u64,

    /// The initial permissions associated with the region.
    pub perm: Perm,

    /// The (initial) content of the mapping.
    pub value: Value,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub enum Value {
    /// The region should be marked as byte mapped but uninitalized.
    None,

    /// The region should be byte-mapped and filled with the specified value.
    Fill(u8),

    /// The region should be byte-mapped and initialized with the specified value.
    Bytes(Vec<u8>),

    /// Value should be resolved using the IO handler.
    Io,

    /// Writes should be logged.
    LogWrite,
}

#[derive(Debug, serde::Deserialize)]
pub enum Perm {
    None,
    R,
    W,
    X,
    RX,
    RW,
    WX,
    RWX,
}

impl Perm {
    pub fn value(&self) -> u8 {
        match self {
            Self::None => perm::NONE,
            Self::R => perm::READ,
            Self::W => perm::WRITE,
            Self::X => perm::EXEC,
            Self::RX => perm::READ | perm::EXEC,
            Self::RW => perm::READ | perm::WRITE,
            Self::WX => perm::WRITE | perm::EXEC,
            Self::RWX => perm::READ | perm::WRITE | perm::EXEC,
        }
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct Interrupt {
    /// The symbol assocated with the handler function for this interrupt.
    pub isr: String,

    /// The symbol associated with the address and bit mask that determines whether the interrupt
    /// is enabled or not.
    pub enable: (String, u64),

    /// The symbol associated with the address and the bit that should be set when this interrupt
    /// is triggered.
    pub flag: (String, u64),
}

#[derive(Debug, serde::Deserialize)]
pub enum Peripheral {
    /// Logs writes to stdout.
    LogWrite,

    /// Always returns a constant 8-bit value when read.
    Byte(u8),

    /// Always returns a constant 16-bit value when read.
    Word(u16),
}
