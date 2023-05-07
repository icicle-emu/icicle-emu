use std::collections::HashMap;

use icicle_vm::cpu::{mem::perm, utils::get_u64, Exception, ExceptionCode};

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CustomSetup {
    #[serde(default)]
    pub hooks: HashMap<u64, Hooks>,
    #[serde(default)]
    pub extra_memory: Vec<Memory>,
    #[serde(default)]
    pub initialize: Vec<Initialize>,
    #[serde(default, deserialize_with = "deserialize_input")]
    pub input: Vec<u8>,
}

impl CustomSetup {
    pub fn configure(&mut self, vm: &mut icicle_vm::Vm) -> anyhow::Result<()> {
        for (addr, kind) in &self.hooks {
            match kind {
                Hooks::Exit => vm.hook_address(*addr, |cpu, addr| {
                    cpu.exception = Exception::new(ExceptionCode::Halt, addr);
                }),
                Hooks::Crash => vm.hook_address(*addr, |cpu, addr| {
                    cpu.exception = Exception::new(ExceptionCode::ExecViolation, addr);
                }),
            }
        }

        for entry in &self.extra_memory {
            vm.cpu.mem.map_memory_len(entry.offset, entry.size, icicle_vm::cpu::mem::Mapping {
                perm: entry.perm.value() | perm::INIT,
                value: 0x00,
            });
        }

        // Precompute all register locations to avoid lookups in `init`.
        for entry in &mut self.initialize {
            if let Location::Reg(name) = &mut entry.location {
                let var = vm
                    .cpu
                    .arch
                    .sleigh
                    .get_reg(name)
                    .ok_or_else(|| anyhow::format_err!("unknown register: {name}"))?
                    .var;
                entry.location = Location::VarNode(var);
            }
        }

        Ok(())
    }

    pub fn init(&self, vm: &mut icicle_vm::Vm, buf: &mut Vec<u8>) -> anyhow::Result<()> {
        for entry in &self.initialize {
            buf.clear();
            match &entry.value {
                Value::U64(x) => buf.extend_from_slice(&x.to_le_bytes()),
                Value::U32(x) => buf.extend_from_slice(&x.to_le_bytes()),
                Value::InputLength => {
                    buf.extend_from_slice(&(self.input.len() as u32).to_le_bytes())
                }
                Value::InputData => buf.extend_from_slice(&self.input),
            }

            match &entry.location {
                Location::Reg(_) => {
                    unreachable!("reg should have been converted to varnode in configure")
                }
                Location::VarNode(var) => {
                    let reg = vm.cpu.regs.get_mut(*var).unwrap();
                    let len = buf.len().min(reg.len());
                    reg[..len].copy_from_slice(&buf[..len]);
                }
                Location::StartAddr => {
                    buf.resize(8, 0);
                    vm.cpu.write_pc(get_u64(buf));
                }
                Location::Mem(addr) => {
                    vm.cpu
                        .mem
                        .write_bytes_large(*addr, buf, perm::NONE)
                        .map_err(|e| anyhow::format_err!("failed to write to {addr:#x}: {e:?}"))?;
                }
            }
        }

        Ok(())
    }
}

fn deserialize_input<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    enum BytesOrString {
        Bytes(Vec<u8>),
        String(String),
    }
    let bytes_or_string: BytesOrString = serde::Deserialize::deserialize(deserializer)?;
    match bytes_or_string {
        BytesOrString::Bytes(bytes) => Ok(bytes),
        BytesOrString::String(string) => Ok(string.into_bytes()),
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub enum Hooks {
    /// Trigger an immediate exit at the given location.
    Exit,
    /// Trigger a crash at the given location.
    Crash,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Memory {
    pub offset: u64,
    pub size: u64,
    pub perm: Perm,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Initialize {
    pub location: Location,
    pub value: Value,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub enum Location {
    Reg(String),
    #[serde(skip)]
    VarNode(pcode::VarNode),
    StartAddr,
    Mem(u64),
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub enum Value {
    U32(u32),
    U64(u64),
    InputLength,
    InputData,
}

#[derive(Copy, Clone, serde::Deserialize, serde::Serialize)]
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
