//! Architecture specific components

mod aarch64;
mod mips;
mod riscv64;
pub mod x86;

use icicle_cpu::{
    mem::{MemError, MemResult},
    utils::align_up,
};
use target_lexicon::{Aarch64Architecture, Architecture, CDataModel, Endianness, Triple};

use crate::{types, LinuxCpu, LinuxError, LinuxMmu, LinuxResult};

pub enum Dynamic {
    Aarch64(aarch64::Aarch64),
    Mips32(mips::Mips32),
    Riscv64(riscv64::Riscv64),
    X64(x86::x64::X64),
    I386(x86::i386::I386),
}

macro_rules! dispatch {
    ($this:expr, $ident:ident, $expr:expr) => {
        match $this {
            Dynamic::Aarch64($ident) => $expr,
            Dynamic::Mips32($ident) => $expr,
            Dynamic::Riscv64($ident) => $expr,
            Dynamic::X64($ident) => $expr,
            Dynamic::I386($ident) => $expr,
        }
    };
}

/// Syscall abstraction layer
pub trait ArchSyscall {
    /// Get the nth argument of the system call according to the current calling convention.
    fn get_arg<C: LinuxCpu>(&self, cpu: &mut C, n: usize) -> LinuxResult;

    fn get_args<C: LinuxCpu, const N: usize>(&self, cpu: &mut C) -> Result<[u64; N], LinuxError> {
        let mut args = [0; N];
        for (i, arg) in args.iter_mut().enumerate() {
            *arg = self.get_arg(cpu, i)?;
        }
        Ok(args)
    }

    /// Writes the syscall result `result` to the cpu, clearning errno
    fn set_result<C: LinuxCpu>(&self, cpu: &mut C, result: u64);

    /// Writes the syscall error code `err` to architecture specific errno location
    fn set_error<C: LinuxCpu>(&self, cpu: &mut C, err: u64);

    fn init_vdso<C: LinuxCpu>(&mut self, _cpu: &mut C) -> MemResult<()> {
        Ok(())
    }

    /// Sets up the context required to invoke signal handlers
    fn setup_signal_frame<C: LinuxCpu>(
        &self,
        _cpu: &mut C,
        _signal: u64,
        _sigaction: &types::Sigaction,
    ) -> MemResult<()> {
        tracing::error!("Signals are not supported on the current architecture");
        Err(MemError::Unknown)
    }

    fn restore_signal_frame<C: LinuxCpu>(&self, _cpu: &mut C) -> MemResult<()> {
        Ok(())
    }
}

impl Dynamic {
    pub fn get_arg<C: LinuxCpu>(&self, cpu: &mut C, n: usize) -> LinuxResult {
        dispatch!(self, inner, inner.get_arg(cpu, n))
    }

    pub fn get_args<C: LinuxCpu, const N: usize>(
        &self,
        cpu: &mut C,
    ) -> Result<[u64; N], LinuxError> {
        dispatch!(self, inner, inner.get_args(cpu))
    }

    pub fn set_result<C: LinuxCpu>(&self, cpu: &mut C, result: u64) {
        dispatch!(self, inner, inner.set_result(cpu, result))
    }

    pub fn set_error<C: LinuxCpu>(&self, cpu: &mut C, err: u64) {
        dispatch!(self, inner, inner.set_error(cpu, err))
    }

    pub fn init_vdso<C: LinuxCpu>(&mut self, cpu: &mut C) -> MemResult<()> {
        dispatch!(self, inner, inner.init_vdso(cpu))
    }

    /// Sets up the context required to invoke signal handlers
    pub fn setup_signal_frame<C: LinuxCpu>(
        &self,
        cpu: &mut C,
        signal: u64,
        sigaction: &types::Sigaction,
    ) -> MemResult<()> {
        dispatch!(self, inner, inner.setup_signal_frame(cpu, signal, sigaction))
    }

    pub fn restore_signal_frame<C: LinuxCpu>(&self, cpu: &mut C) -> MemResult<()> {
        dispatch!(self, inner, inner.restore_signal_frame(cpu))
    }

    pub fn syscall_names(&self) -> &'static [&'static str] {
        match self {
            Dynamic::Aarch64(_) => &aarch64::SYSCALL_NAMES[..],
            Dynamic::Mips32(_) => &mips::SYSCALL_NAMES[..],
            Dynamic::Riscv64(_) => &riscv64::SYSCALL_NAMES[..],
            Dynamic::X64(_) => &x86::x64::SYSCALL_NAMES[..],
            Dynamic::I386(_) => &x86::i386::SYSCALL_NAMES[..],
        }
    }

    pub fn syscall_mapping(&self) -> &'static [usize] {
        match self {
            Dynamic::Aarch64(_) => &aarch64::SYSCALL_MAPPING[..],
            Dynamic::Mips32(_) => &mips::SYSCALL_MAPPING[..],
            Dynamic::Riscv64(_) => &riscv64::SYSCALL_MAPPING[..],
            Dynamic::X64(_) => &x86::x64::SYSCALL_MAPPING[..],
            Dynamic::I386(_) => &x86::i386::SYSCALL_MAPPING[..],
        }
    }

    pub fn syscall_offset(&self) -> usize {
        match self {
            Dynamic::Mips32(_) => 4000,
            _ => 0,
        }
    }
}

macro_rules! encode_bytes {
    ($arch:expr, $value:expr) => {
        match $arch.endianness {
            Endianness::Little => $value.to_le_bytes(),
            Endianness::Big => $value.to_be_bytes(),
        }
    };
}

/// Architecture abstraction layer
pub struct KernelArch {
    /// The target triple for the current architecture.
    pub triple: Triple,

    /// The byte order for the current architecture.
    pub endianness: Endianness,

    /// String representation for the current platform
    pub platform_name: Vec<u8>,

    /// The varnode that contains the instruction pointer.
    pub reg_pc: pcode::VarNode,

    /// The varnode that contains the stack pointer.
    pub reg_sp: pcode::VarNode,

    /// Dynamic information about the current architecture.
    pub dynamic: Dynamic,
}

impl KernelArch {
    pub fn new(arch: &icicle_cpu::Arch) -> Self {
        let dynamic = match arch.triple.architecture {
            Architecture::X86_32(_) => Dynamic::I386(x86::i386::I386::new(arch)),
            Architecture::X86_64 => Dynamic::X64(x86::x64::X64::new(arch)),
            Architecture::Mips32(_) => Dynamic::Mips32(mips::Mips32::new(arch)),
            Architecture::Aarch64(Aarch64Architecture::Aarch64) => {
                Dynamic::Aarch64(aarch64::Aarch64::new(arch))
            }
            Architecture::Riscv64(_) => Dynamic::Riscv64(riscv64::Riscv64::new(arch)),
            unknown => unimplemented!("unsupported Linux architecture: {}", unknown),
        };

        let mut platform_name = arch.triple.to_string().into_bytes();
        platform_name.push(0);

        Self {
            triple: arch.triple.clone(),
            endianness: arch.triple.endianness().unwrap(),
            platform_name,
            reg_pc: arch.reg_pc,
            reg_sp: arch.reg_sp,
            dynamic,
        }
    }

    /// Gets the original ID of the current syscall.
    pub fn get_guest_syscall_id<C: LinuxCpu>(&self, cpu: &mut C) -> usize {
        let offset = self.dynamic.syscall_offset();
        (self.dynamic.get_arg(cpu, 0).unwrap() as usize).saturating_sub(offset)
    }

    /// Gets the translated ID of the current syscall.
    pub fn get_syscall_id<C: LinuxCpu>(&self, cpu: &mut C) -> usize {
        let guest_syscall_id = self.get_guest_syscall_id(cpu);
        *self.dynamic.syscall_mapping().get(guest_syscall_id).unwrap_or(&0)
    }

    /// Returns the name of the current syscall.
    pub fn get_syscall_name<C: LinuxCpu>(&self, cpu: &mut C) -> &'static str {
        self.dynamic.syscall_names().get(self.get_guest_syscall_id(cpu)).unwrap_or(&"unknown")
    }

    /// Gets stack alignment requirements
    pub fn stack_alignment(&self) -> u64 {
        self.triple.pointer_width().map_or(4, |x| x.bytes() as u64)
    }

    /// Pushes a pointer sized value onto the stack, returning the new stack pointer
    pub fn push_ptr<C: LinuxCpu>(&self, cpu: &mut C, ptr: u64) -> MemResult<u64> {
        match self.triple.pointer_width().map_or(4, |x| x.bytes() as u64) {
            4 => self.push_bytes(cpu, &encode_bytes!(self, ptr as u32)),
            8 => self.push_bytes(cpu, &encode_bytes!(self, ptr)),
            other => panic!("bad data type size: {}", other),
        }
    }

    /// Pushes bytes onto the stack preserving alignment, returns the new stack pointer
    pub fn push_bytes<C: LinuxCpu>(&self, cpu: &mut C, bytes: &[u8]) -> MemResult<u64> {
        let aligned_len = align_up(bytes.len() as u64, self.stack_alignment());
        let stack_ptr = match cpu.read_var(self.reg_sp).checked_sub(aligned_len) {
            Some(addr) => addr,
            None => return Err(MemError::WriteViolation),
        };

        cpu.mem().write_bytes(stack_ptr, bytes)?;
        cpu.write_var(self.reg_sp, stack_ptr);

        Ok(stack_ptr)
    }

    pub fn libc(&self, offset: u64) -> Libc {
        Libc {
            arch: self.triple.architecture,
            data_model: self.triple.data_model().expect("unknown data model"),
            endianness: self.endianness,
            offset,
        }
    }
}

pub trait CDataType {
    const SIGNED: bool = false;
    fn size(model: &CDataModel) -> u64;
    fn alignment(model: &CDataModel) -> u64 {
        Self::size(model)
    }
}

macro_rules! impl_fixed_size {
    ($name:ident, $bytes:expr, $signed:expr) => {
        pub struct $name;

        impl CDataType for $name {
            const SIGNED: bool = $signed;
            fn size(_model: &CDataModel) -> u64 {
                $bytes
            }
        }
    };
}

impl_fixed_size!(U8, 1, false);
impl_fixed_size!(S8, 1, true);
impl_fixed_size!(U16, 2, false);
impl_fixed_size!(S16, 2, true);
impl_fixed_size!(U32, 4, false);
impl_fixed_size!(S32, 4, true);

pub struct UByte;
impl CDataType for UByte {
    fn size(_model: &CDataModel) -> u64 {
        1
    }
}

pub struct SByte;
impl CDataType for SByte {
    const SIGNED: bool = true;
    fn size(_model: &CDataModel) -> u64 {
        1
    }
}

pub struct UShort;
impl CDataType for UShort {
    fn size(model: &CDataModel) -> u64 {
        model.short_size().bytes() as u64
    }
}

pub struct SShort;
impl CDataType for SShort {
    const SIGNED: bool = true;
    fn size(model: &CDataModel) -> u64 {
        model.short_size().bytes() as u64
    }
}

pub struct UInt;
impl CDataType for UInt {
    fn size(model: &CDataModel) -> u64 {
        model.int_size().bytes() as u64
    }
}

pub struct SInt;
impl CDataType for SInt {
    const SIGNED: bool = true;
    fn size(model: &CDataModel) -> u64 {
        model.int_size().bytes() as u64
    }
}

pub struct ULong;
impl CDataType for ULong {
    fn size(model: &CDataModel) -> u64 {
        model.long_size().bytes() as u64
    }
}

pub struct SLong;
impl CDataType for SLong {
    const SIGNED: bool = true;
    fn size(model: &CDataModel) -> u64 {
        model.long_size().bytes() as u64
    }
}

pub struct ULongLong;
impl CDataType for ULongLong {
    fn size(model: &CDataModel) -> u64 {
        model.long_long_size().bytes() as u64
    }
}

pub struct Ptr;
impl CDataType for Ptr {
    fn size(model: &CDataModel) -> u64 {
        model.pointer_width().bytes() as u64
    }
}

pub trait Struct: Sized {
    fn read<M: LinuxMmu>(libc: &mut Libc, mem: &mut M) -> MemResult<Self>;
    fn write<M: LinuxMmu>(&self, libc: &mut Libc, mmu: &mut M) -> MemResult<()>;
}

pub struct Value<T> {
    pub value: u64,
    ty: std::marker::PhantomData<T>,
}

impl<T> std::fmt::Debug for Value<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.value.fmt(f)
    }
}

impl<T> Default for Value<T> {
    fn default() -> Self {
        Self { value: 0, ty: std::marker::PhantomData }
    }
}

impl<T> Clone for Value<T> {
    fn clone(&self) -> Self {
        Self { ..*self }
    }
}

impl<T> Copy for Value<T> {}

impl<T: CDataType> From<u64> for Value<T> {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl<T: CDataType> Value<T> {
    pub fn new(value: u64) -> Self {
        Self { value, ty: std::marker::PhantomData }
    }
}

impl<T: CDataType> Struct for Value<T> {
    fn read<M: LinuxMmu>(libc: &mut Libc, mem: &mut M) -> MemResult<Self> {
        Ok(Value::new(libc.read::<T, _>(mem)?))
    }

    fn write<M: LinuxMmu>(&self, libc: &mut Libc, mem: &mut M) -> MemResult<()> {
        libc.write::<T, _>(mem, self.value)
    }
}

/// A structure for interacting with memory using libc sizes for the target architecture
#[derive(Clone)]
pub struct Libc {
    pub arch: Architecture,
    pub data_model: CDataModel,
    pub endianness: Endianness,
    offset: u64,
}

impl Libc {
    pub fn write_bytes<M: LinuxMmu>(&mut self, mem: &mut M, bytes: &[u8]) -> MemResult<()> {
        mem.write_bytes(self.offset, bytes)?;
        self.offset += bytes.len() as u64;
        Ok(())
    }

    pub fn read_bytes<M: LinuxMmu>(&mut self, mem: &mut M, bytes: &mut [u8]) -> MemResult<()> {
        mem.read_bytes(self.offset, bytes)?;
        self.offset += bytes.len() as u64;
        Ok(())
    }

    pub fn read<T: CDataType, M: LinuxMmu>(&mut self, mem: &mut M) -> MemResult<u64> {
        let size = T::size(&self.data_model);
        self.offset = align_up(self.offset, T::alignment(&self.data_model));
        let mut buf = [0u8; 8];
        match size {
            1 => mem.read_bytes(self.offset, &mut buf[..1])?,
            2 => mem.read_bytes(self.offset, &mut buf[..2])?,
            4 => mem.read_bytes(self.offset, &mut buf[..4])?,
            8 => mem.read_bytes(self.offset, &mut buf[..8])?,
            _ => panic!("Bad data type size: {}", size),
        };
        let value = u64::from_le_bytes(buf);

        self.offset += size;
        let value = self.bswap::<T>(value);
        Ok(if T::SIGNED { pcode::sxt64(value, size * 8) } else { value })
    }

    pub fn read_struct<T: Struct, M: LinuxMmu>(&mut self, mem: &mut M) -> MemResult<T> {
        T::read(self, mem)
    }

    pub fn write<T: CDataType, M: LinuxMmu>(&mut self, mem: &mut M, val: u64) -> MemResult<()> {
        let val = self.bswap::<T>(val).to_le_bytes();

        let size = T::size(&self.data_model);
        self.offset = align_up(self.offset, T::alignment(&self.data_model));
        match size {
            1 => mem.write_bytes(self.offset, &val[..1])?,
            2 => mem.write_bytes(self.offset, &val[..2])?,
            4 => mem.write_bytes(self.offset, &val[..4])?,
            8 => mem.write_bytes(self.offset, &val[..8])?,
            _ => panic!("Bad data type size: {}", size),
        };
        self.offset += size;
        Ok(())
    }

    pub fn write_struct<T: Struct, M: LinuxMmu>(
        &mut self,
        mem: &mut M,
        value: &T,
    ) -> MemResult<()> {
        value.write(self, mem)
    }

    fn bswap<T: CDataType>(&self, value: u64) -> u64 {
        if self.endianness == Endianness::Little {
            return value;
        }
        match T::size(&self.data_model) {
            1 => value,
            2 => (value as u16).swap_bytes() as u64,
            4 => (value as u32).swap_bytes() as u64,
            8 => value.swap_bytes(),
            size => panic!("Bad data type size: {}", size),
        }
    }

    /// Read a c-string from user-space into `buf`
    pub fn read_cstr<'a, M>(&mut self, mem: &mut M, buf: &'a mut Vec<u8>) -> MemResult<&'a [u8]>
    where
        M: LinuxMmu,
    {
        let start = buf.len();

        let mut addr = self.offset;
        loop {
            let mut byte = [0u8];
            mem.read_bytes(addr, &mut byte)?;
            match byte[0] {
                0 => break,
                x => buf.push(x),
            }
            addr += 1;
        }

        self.offset = addr;

        Ok(&buf[start..])
    }
}

use crate::sys::syscall::{self as sys};

#[derive(Clone, Copy)]
pub enum Handler<C: LinuxCpu> {
    _0(sys::Call0<C>),
    _1(sys::Call1<C>),
    _2(sys::Call2<C>),
    _3(sys::Call3<C>),
    _4(sys::Call4<C>),
    _5(sys::Call5<C>),
    _6(sys::Call6<C>),
}

macro_rules! impl_from {
    ($name:ident, $ty:ident) => {
        impl<C: LinuxCpu> From<sys::$ty<C>> for Handler<C> {
            fn from(inner: sys::$ty<C>) -> Self {
                Self::$name(inner)
            }
        }
    };
}

impl_from!(_0, Call0);
impl_from!(_1, Call1);
impl_from!(_2, Call2);
impl_from!(_3, Call3);
impl_from!(_4, Call4);
impl_from!(_5, Call5);
impl_from!(_6, Call6);
