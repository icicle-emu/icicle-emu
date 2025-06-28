use crate::{arch::ArchSyscall, LinuxCpu, LinuxResult};

#[derive(Clone)]
pub struct Aarch64 {
    args: [pcode::VarNode; 7],
}

impl Aarch64 {
    pub fn new(arch: &icicle_cpu::Arch) -> Self {
        let r = |name: &str| arch.sleigh.get_reg(name).unwrap().var;
        let args = [r("x8"), r("x0"), r("x1"), r("x2"), r("x3"), r("x4"), r("x5")];
        Self { args }
    }
}

impl ArchSyscall for Aarch64 {
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
