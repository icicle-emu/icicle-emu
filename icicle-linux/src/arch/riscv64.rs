use crate::{arch::ArchSyscall, LinuxCpu, LinuxResult};

#[derive(Clone)]
pub struct Riscv64 {
    args: [pcode::VarNode; 7],
}

impl Riscv64 {
    pub fn new(arch: &icicle_cpu::Arch) -> Self {
        let r = |name: &str| arch.sleigh.get_reg(name).unwrap().var;
        let args = [r("a7"), r("a0"), r("a1"), r("a2"), r("a3"), r("a4"), r("a5")];
        Self { args }
    }
}

impl ArchSyscall for Riscv64 {
    fn get_arg<C: LinuxCpu>(&self, cpu: &mut C, n: usize) -> LinuxResult {
        Ok(cpu.read_var(self.args[n]))
    }

    fn set_result<C: LinuxCpu>(&self, cpu: &mut C, result: u64) {
        cpu.write_var(self.args[1], result);
    }

    fn set_error<C: LinuxCpu>(&self, cpu: &mut C, err: u64) {
        cpu.write_var(self.args[1], (-(err as i64)) as u64);
    }
}

pub static SYSCALL_MAPPING: [usize; 600] =
    include!(concat!(env!("OUT_DIR"), "/generic_syscall_mapping.rs"));

pub static SYSCALL_NAMES: [&str; 600] =
    include!(concat!(env!("OUT_DIR"), "/generic_syscall_names.rs"));
