use icicle_cpu::mem::{self, perm, MemResult};

use crate::{arch::ArchSyscall, types, LinuxCpu, LinuxMmu, LinuxResult};

#[allow(unused, bad_style)]
mod reg {
    pub const zero: usize = 0;
    pub const at: usize = 1;
    pub const v0: usize = 2;
    pub const v1: usize = 3;
    pub const a0: usize = 4;
    pub const a1: usize = 5;
    pub const a2: usize = 6;
    pub const a3: usize = 7;
    pub const t0: usize = 8;
    pub const t1: usize = 9;
    pub const t2: usize = 10;
    pub const t3: usize = 11;
    pub const t4: usize = 12;
    pub const t5: usize = 13;
    pub const t6: usize = 14;
    pub const t7: usize = 15;
    pub const s0: usize = 16;
    pub const s1: usize = 17;
    pub const s2: usize = 18;
    pub const s3: usize = 19;
    pub const s4: usize = 20;
    pub const s5: usize = 21;
    pub const s6: usize = 22;
    pub const s7: usize = 23;
    pub const t8: usize = 24;
    pub const t9: usize = 25;
    pub const k0: usize = 26;
    pub const k1: usize = 27;
    pub const gp: usize = 28;
    pub const sp: usize = 29;
    pub const s8: usize = 30;
    pub const ra: usize = 31;
    pub const pc: usize = 32;
}

#[derive(Clone)]
pub struct Mips32 {
    regs: [pcode::VarNode; 33],
    rt_sigreturn_vdso: u64,
    is_be: bool,
}

impl Mips32 {
    #[rustfmt::skip]
    pub fn new(arch: &icicle_cpu::Arch) -> Self {
        let r = |name: &str| arch.sleigh.get_reg(name).unwrap().var;
        Self {
            regs: [
                r("zero"), r("at"), r("v0"), r("v1"),
                r("a0"), r("a1"), r("a2"), r("a3"),
                r("t0"), r("t1"), r("t2"), r("t3"),
                r("t4"), r("t5"), r("t6"), r("t7"),
                r("s0"), r("s1"), r("s2"), r("s3"),
                r("s4"), r("s5"), r("s6"), r("s7"),
                r("t8"), r("t9"), r("k0"), r("k1"),
                r("gp"), r("sp"), r("s8"), r("ra"),
                r("pc"),
            ],
            rt_sigreturn_vdso: 0x0,
            is_be: arch.sleigh.big_endian,
        }
    }

    fn read_u32<M: LinuxMmu>(&self, mem: &mut M, addr: u64) -> MemResult<u32> {
        let mut buf = [0u8; 4];
        mem.read_bytes(addr, &mut buf)?;
        Ok(match self.is_be {
            true => u32::from_be_bytes(buf),
            false => u32::from_le_bytes(buf),
        })
    }

    fn write_u32<M: LinuxMmu>(&self, mem: &mut M, addr: u64, val: u32) -> MemResult<()> {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&match self.is_be {
            true => val.to_be_bytes(),
            false => val.to_le_bytes(),
        });
        mem.write_bytes(addr, &buf)
    }
}

impl ArchSyscall for Mips32 {
    fn get_arg<C: LinuxCpu>(&self, cpu: &mut C, n: usize) -> LinuxResult {
        Ok(match n {
            // Syscall number and first 4 arguments are taken from registers
            0 => cpu.read_var(self.regs[reg::v0]) as i32 as i64 as u64,
            1 => cpu.read_var(self.regs[reg::a0]) as i32 as i64 as u64,
            2 => cpu.read_var(self.regs[reg::a1]) as i32 as i64 as u64,
            3 => cpu.read_var(self.regs[reg::a2]) as i32 as i64 as u64,
            4 => cpu.read_var(self.regs[reg::a3]) as i32 as i64 as u64,

            // Remaining arguments are taken from the stack
            5 | 6 => {
                let sp = cpu.read_var(self.regs[reg::sp]);
                let addr = sp + (n - 1) as u64 * 4;
                tracing::trace!("n = {n}, sp = {sp:#0x}, read = {addr:#0x}");

                let mut bytes = [0u8; 4];
                cpu.mem().read_bytes(addr, &mut bytes).map_err(|_| addr)?;
                match self.is_be {
                    true => i32::from_be_bytes(bytes) as i64 as u64,
                    false => i32::from_le_bytes(bytes) as i64 as u64,
                }
            }

            _ => unreachable!("There should be no syscall with this many arguments: {}", n),
        })
    }

    fn set_result<C: LinuxCpu>(&self, cpu: &mut C, result: u64) {
        cpu.write_var(self.regs[reg::a3], 0);
        cpu.write_var(self.regs[reg::v0], result);
    }

    fn set_error<C: LinuxCpu>(&self, cpu: &mut C, err: u64) {
        cpu.write_var(self.regs[reg::a3], (-1_i64) as u64);
        cpu.write_var(self.regs[reg::v0], ERRNO_MAPPING[err as usize] as u64);
    }

    fn init_vdso<C: LinuxCpu>(&mut self, cpu: &mut C) -> MemResult<()> {
        const VDSO_SIZE: u64 = crate::sys::PAGE_SIZE;

        let layout = mem::AllocLayout { addr: None, size: VDSO_SIZE, align: crate::sys::PAGE_SIZE };
        let vdso_base = cpu
            .mem()
            .alloc(layout, mem::Mapping { perm: perm::READ | perm::WRITE, value: 0xAA })?;

        let li_v0_sigreturn = u32::from_le_bytes([0x61, 0x10, 0x02, 0x24]); // li v0, 4193 (rt_sigreturn)
        let syscall = u32::from_le_bytes([0x0c, 0x00, 0x00, 0x00]); // syscall

        let mut addr = vdso_base;
        for inst in [li_v0_sigreturn, syscall] {
            let inst = if self.is_be { inst.swap_bytes() } else { inst }.to_le_bytes();
            cpu.mem().write_bytes(addr, &inst)?;
            addr += inst.len() as u64;
        }

        cpu.mem().update_perm(vdso_base, addr - vdso_base, perm::READ | perm::EXEC | perm::INIT)?;

        self.rt_sigreturn_vdso = vdso_base + 0x0;
        tracing::debug!("vdso.rt_sigreturn = {:#0x}", self.rt_sigreturn_vdso);

        Ok(())
    }

    fn setup_signal_frame<C: LinuxCpu>(
        &self,
        cpu: &mut C,
        signal: u64,
        sigaction: &types::Sigaction,
    ) -> MemResult<()> {
        const FRAME_SIZE: u64 = 0x100;

        let prev_sp = cpu.read_var(self.regs[reg::sp]);
        let sp = prev_sp - FRAME_SIZE - 32;

        let pc = cpu.read_var(self.regs[reg::pc]);

        self.write_u32(cpu.mem(), sp, pc as u32 + 4)?;
        for (i, reg) in self.regs.iter().enumerate() {
            let addr = sp + ((i + 1) as u64 * 4);
            let value = cpu.read_var(*reg) as u32;
            self.write_u32(cpu.mem(), addr, value)?;
        }

        // @fixme: create the proper signal frame structure, instead of just saving registers.

        cpu.write_var(self.regs[reg::sp], sp);

        cpu.write_var(self.regs[reg::a0], signal);
        cpu.write_var(self.regs[reg::a1], 0); // @fixme: set correct arguments.
        cpu.write_var(self.regs[reg::a2], 0); // @fixme: set correct arguments.

        cpu.write_var(self.regs[reg::t9], sigaction.handler.value);

        cpu.write_var(self.regs[reg::ra], self.rt_sigreturn_vdso);

        // @fixme
        // cpu.shadow_stack.push((self.rt_sigreturn_vdso, icicle::ilgraph::block::INVALID));

        Ok(())
    }

    fn restore_signal_frame<C: LinuxCpu>(&self, cpu: &mut C) -> MemResult<()> {
        let sp = cpu.read_var(self.regs[reg::sp]);

        let next_pc = self.read_u32(cpu.mem(), sp)? as u64;
        for (i, reg) in self.regs.iter().enumerate() {
            let addr = sp + ((i + 1) as u64 * 4);
            let value = self.read_u32(cpu.mem(), addr)? as u64;
            cpu.write_var(*reg, value);
        }
        cpu.write_var(self.regs[reg::pc], next_pc);

        // @fixme: this should be set as part of other signal handling code.
        self.set_error(cpu, crate::errno::EINTR);

        Ok(())
    }
}

pub static SYSCALL_MAPPING: [usize; 600] =
    include!(concat!(env!("OUT_DIR"), "/mips_syscall_mapping.rs"));

pub static SYSCALL_NAMES: [&str; 600] =
    include!(concat!(env!("OUT_DIR"), "/mips_syscall_names.rs"));

static ERRNO_MAPPING: [u32; 133] = include!(concat!(env!("OUT_DIR"), "/mips_errno.rs"));
