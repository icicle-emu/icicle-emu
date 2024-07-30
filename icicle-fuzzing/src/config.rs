use std::{collections::HashMap, io::Write};

use anyhow::Context;
use icicle_vm::cpu::{
    mem::perm,
    utils::{get_u64, parse_u64_with_prefix},
    Exception, ExceptionCode, ValueSource,
};

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CustomSetup {
    #[serde(default)]
    pub hooks: HashMap<AddrOrSymbol, Hooks>,
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
            let addr = match addr {
                AddrOrSymbol::Addr(addr) => *addr,
                AddrOrSymbol::Symbol(sym) => {
                    lookup_symbol(vm, &sym).with_context(|| format!("failed to lookup: {sym}"))?
                }
            };

            match kind {
                Hooks::Exit => vm.hook_address(addr, |cpu, addr| {
                    cpu.exception = Exception::new(ExceptionCode::Halt, addr);
                }),
                Hooks::Crash => vm.hook_address(addr, |cpu, addr| {
                    cpu.exception = Exception::new(ExceptionCode::ExecViolation, addr);
                }),
                Hooks::Assert(_expr) => vm.hook_address(addr, |cpu, addr| {
                    cpu.exception = Exception::new(ExceptionCode::ExecViolation, addr);
                }),
                Hooks::PrintChar(reg) => {
                    let reg = vm.cpu.arch.sleigh.get_reg(reg).unwrap().var;
                    vm.hook_address(addr, move |cpu: &mut icicle_vm::cpu::Cpu, _| {
                        let char = cpu.read_var::<u32>(reg);
                        print!("{}", char as u8 as char);
                        let _ = std::io::stdout().flush();
                    });
                }
                Hooks::PrintStrSlice(data_reg, len_reg) => {
                    let data = vm.cpu.arch.sleigh.get_reg(data_reg).unwrap().var;
                    let len = vm.cpu.arch.sleigh.get_reg(len_reg).unwrap().var;

                    let mut buf = vec![];
                    vm.hook_address(addr, move |cpu: &mut icicle_vm::cpu::Cpu, _| {
                        let ptr = cpu.read_var::<u32>(data);
                        let len = cpu.read_var::<u32>(len);
                        buf.resize((len as usize).min(64), 0);
                        let _ = cpu.mem.read_bytes(ptr as u64, &mut buf, perm::NONE);
                        print!("{}", String::from_utf8_lossy(&buf));
                        let _ = std::io::stdout().flush();
                    });
                }
                Hooks::PrintCstr(reg) => {
                    let reg = vm.cpu.arch.sleigh.get_reg(reg).unwrap().var;
                    let mut buf = [0; 64];
                    vm.hook_address(addr, move |cpu: &mut icicle_vm::cpu::Cpu, _| {
                        let ptr = cpu.read_var::<u32>(reg) as u64;
                        print!("{}", String::from_utf8_lossy(&read_cstr(&mut buf, cpu, ptr)));
                        let _ = std::io::stdout().flush();
                    });
                }
                Hooks::PrintLnCstr(reg) => {
                    let reg = vm.cpu.arch.sleigh.get_reg(reg).unwrap().var;
                    let mut buf = [0; 64];
                    vm.hook_address(addr, move |cpu: &mut icicle_vm::cpu::Cpu, _| {
                        let ptr = cpu.read_var::<u32>(reg) as u64;
                        println!("{}", String::from_utf8_lossy(&read_cstr(&mut buf, cpu, ptr)));
                        let _ = std::io::stdout().flush();
                    });
                }
            }
        }

        for entry in &self.extra_memory {
            vm.cpu.mem.map_memory_len(entry.offset, entry.size, icicle_vm::cpu::mem::Mapping {
                perm: entry.perm.value() | perm::INIT,
                value: 0x00,
            });
        }

        // Precompute all register and symbols locations to avoid lookups in `init`.
        for entry in &mut self.initialize {
            if let Location::Reg(name) = &entry.location {
                let var = vm
                    .cpu
                    .arch
                    .sleigh
                    .get_reg(name)
                    .ok_or_else(|| anyhow::format_err!("unknown register: {name}"))?
                    .var;
                entry.location = Location::VarNode(var);
            }
            if let Location::Symbol(sym) = &entry.location {
                let addr =
                    lookup_symbol(vm, &sym).with_context(|| format!("failed to lookup: {sym}"))?;
                entry.location = Location::Mem(addr);
            }
            preprocess_value(&mut entry.value, vm)?;
        }

        Ok(())
    }

    pub fn init(&self, vm: &mut icicle_vm::Vm, buf: &mut Vec<u8>) -> anyhow::Result<()> {
        for entry in &self.initialize {
            buf.clear();
            self.get_value(&mut vm.cpu, &entry.value, buf)?;

            match &entry.location {
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
                Location::Reg(_) | Location::Symbol(_) => unreachable!("translated in `configure`"),
            }
        }

        Ok(())
    }

    fn get_value(
        &self,
        cpu: &mut icicle_vm::cpu::Cpu,
        value: &Value,
        buf: &mut Vec<u8>,
    ) -> anyhow::Result<()> {
        match value {
            Value::U8(x) => buf.extend_from_slice(&x.to_le_bytes()),
            Value::U16(x) => buf.extend_from_slice(&x.to_le_bytes()),
            Value::U32(x) => buf.extend_from_slice(&x.to_le_bytes()),
            Value::U64(x) => buf.extend_from_slice(&x.to_le_bytes()),
            Value::Bytes(x) => buf.extend_from_slice(&x),
            Value::InputLength => buf.extend_from_slice(&(self.input.len() as u32).to_le_bytes()),
            Value::InputData => buf.extend_from_slice(&self.input),
            Value::Mem(AddrOrSymbol::Addr(addr), size) => {
                buf.resize(*size, 0);
                cpu.mem.read_bytes(*addr, buf, perm::NONE)?;
            }
            Value::Symbol(_) | Value::Mem(AddrOrSymbol::Symbol(_), _) => {
                unreachable!("translated in `configure`")
            }
        }
        Ok(())
    }
}

fn preprocess_value(value: &mut Value, vm: &mut icicle_vm::Vm) -> anyhow::Result<()> {
    if let Value::Symbol(sym) = value {
        let addr = lookup_symbol(vm, &sym).with_context(|| format!("failed to lookup: {sym}"))?;
        *value = Value::U64(addr);
    }
    if let Value::Mem(AddrOrSymbol::Symbol(sym), size) = value {
        let addr = lookup_symbol(vm, &sym).with_context(|| format!("failed to lookup: {sym}"))?;
        *value = Value::Mem(AddrOrSymbol::Addr(addr), *size);
    }
    Ok(())
}

fn lookup_symbol(vm: &mut icicle_vm::Vm, sym: &str) -> anyhow::Result<u64, anyhow::Error> {
    let (base, offset) = match sym.split_once("+") {
        Some((base, offset)) => (
            base,
            parse_u64_with_prefix(offset)
                .ok_or_else(|| anyhow::format_err!("error parsing symbol with offset: {sym}"))?,
        ),
        None => (sym, 0),
    };

    let debug = vm.env.debug_info().ok_or_else(|| anyhow::format_err!("debug info missing"))?;
    Ok(debug.symbols.resolve_sym(base).ok_or_else(|| anyhow::format_err!("symbol not found"))?
        + offset)
}

fn read_cstr<'a>(buf: &'a mut [u8], cpu: &mut icicle_vm::cpu::Cpu, ptr: u64) -> &'a [u8] {
    buf[0] = 0;
    let _ = cpu.mem.read_bytes(ptr, buf, perm::NONE);
    let len = buf.iter().position(|x| *x == 0).unwrap_or(buf.len());
    &buf[..len]
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
pub enum Expr {
    Eq(Value, Value),
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub enum Hooks {
    /// Trigger an immediate exit at the given location.
    Exit,
    /// Trigger a crash at the given location.
    Crash,
    /// Assert that a condition is true, otherwise exit with a crash.
    Assert(Expr),
    /// Print the character in the provided register to stdout.
    PrintChar(String),
    /// Print string slice (pointer, len) to stdout.
    PrintStrSlice(String, String),
    /// Print c-string pointed to by the provided register to stdout.
    PrintCstr(String),
    /// Print c-string pointed to by the provided register to stdout with a newline.
    PrintLnCstr(String),
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
    Symbol(String),
}

#[derive(Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum AddrOrSymbol {
    Addr(u64),
    Symbol(String),
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub enum Value {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    Bytes(Vec<u8>),
    Symbol(String),
    InputLength,
    InputData,
    Mem(AddrOrSymbol, usize),
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
