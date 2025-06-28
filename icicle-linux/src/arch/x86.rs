use crate::{arch::ArchSyscall, LinuxCpu, LinuxResult};

#[derive(Debug)]
pub struct GDTEntry {
    pub base: u32,
    pub limit: u32,
    pub flags: u8,
    pub access: u8,
}

impl GDTEntry {
    #[allow(unused)]
    pub fn from_bytes(b: [u8; 8]) -> Self {
        Self {
            base: u32::from_le_bytes([b[2], b[3], b[4], b[7]]),
            limit: (u16::from_le_bytes([b[0], b[1]]) as u32) | ((b[6] & 0xf) as u32),
            access: b[5],
            flags: b[6] >> 4,
        }
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        let b = self.base.to_le_bytes();
        let l = self.limit.to_le_bytes();
        [l[0], l[1], b[0], b[1], b[2], self.access, (self.flags << 4) | (l[3] & 0xf), b[3]]
    }
}

pub mod x64 {
    use super::*;

    #[derive(Clone)]
    pub struct X64 {
        rax: pcode::VarNode,
        rdi: pcode::VarNode,
        rsi: pcode::VarNode,
        rdx: pcode::VarNode,
        r10: pcode::VarNode,
        r8: pcode::VarNode,
        r9: pcode::VarNode,
    }

    impl X64 {
        pub fn new(arch: &icicle_cpu::Arch) -> Self {
            let r = |name: &str| arch.sleigh.get_reg(name).unwrap().var;
            Self {
                rax: r("RAX"),
                rdi: r("RDI"),
                rsi: r("RSI"),
                rdx: r("RDX"),
                r10: r("R10"),
                r8: r("R8"),
                r9: r("R9"),
            }
        }
    }

    impl ArchSyscall for X64 {
        fn get_arg<C: LinuxCpu>(&self, cpu: &mut C, n: usize) -> LinuxResult {
            Ok(match n {
                0 => cpu.read_var(self.rax),
                1 => cpu.read_var(self.rdi),
                2 => cpu.read_var(self.rsi),
                3 => cpu.read_var(self.rdx),
                4 => cpu.read_var(self.r10),
                5 => cpu.read_var(self.r8),
                6 => cpu.read_var(self.r9),
                _ => unreachable!("There should be no syscall with this many arguments: {}", n),
            })
        }

        fn set_result<C: LinuxCpu>(&self, cpu: &mut C, result: u64) {
            cpu.write_var(self.rax, result);
        }

        fn set_error<C: LinuxCpu>(&self, cpu: &mut C, err: u64) {
            cpu.write_var(self.rax, (-(err as i64)) as u64);
        }
    }

    pub static SYSCALL_MAPPING: [usize; 600] =
        include!(concat!(env!("OUT_DIR"), "/x64_syscall_mapping.rs"));

    pub static SYSCALL_NAMES: [&str; 600] =
        include!(concat!(env!("OUT_DIR"), "/x64_syscall_names.rs"));
}

pub mod i386 {
    use super::*;

    #[derive(Clone)]
    pub struct I386 {
        eax: pcode::VarNode,
        ebx: pcode::VarNode,
        ecx: pcode::VarNode,
        edx: pcode::VarNode,
        esi: pcode::VarNode,
        edi: pcode::VarNode,
        ebp: pcode::VarNode,
    }

    impl I386 {
        pub fn new(arch: &icicle_cpu::Arch) -> Self {
            let r = |name: &str| arch.sleigh.get_reg(name).unwrap().var;
            Self {
                eax: r("EAX"),
                ebx: r("EBX"),
                ecx: r("ECX"),
                edx: r("EDX"),
                esi: r("ESI"),
                edi: r("EDI"),
                ebp: r("EBP"),
            }
        }
    }

    impl ArchSyscall for I386 {
        fn get_arg<C: LinuxCpu>(&self, cpu: &mut C, n: usize) -> LinuxResult {
            Ok(match n {
                0 => cpu.read_var(self.eax),
                1 => cpu.read_var(self.ebx),
                2 => cpu.read_var(self.ecx),
                3 => cpu.read_var(self.edx),
                4 => cpu.read_var(self.esi),
                5 => cpu.read_var(self.edi),
                6 => cpu.read_var(self.ebp),
                _ => unreachable!("There should be no syscall with this many arguments: {}", n),
            })
        }

        fn set_result<C: LinuxCpu>(&self, cpu: &mut C, result: u64) {
            cpu.write_var(self.eax, result);
        }

        fn set_error<C: LinuxCpu>(&self, cpu: &mut C, err: u64) {
            cpu.write_var(self.eax, -(err as i32) as u64);
        }
    }

    pub static SYSCALL_MAPPING: [usize; 600] =
        include!(concat!(env!("OUT_DIR"), "/i386_syscall_mapping.rs"));

    pub static SYSCALL_NAMES: [&str; 600] =
        include!(concat!(env!("OUT_DIR"), "/i386_syscall_names.rs"));
}
