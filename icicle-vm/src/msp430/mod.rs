pub mod config;
mod env;
mod hw;

pub use self::{
    config::{Config, Mcu},
    env::Msp430,
};

use icicle_cpu::ValueSource;
use sleigh_runtime::SleighData;

use crate::cpu::Cpu;

pub struct StatusRegHandler {
    pub cf: pcode::VarNode,
    pub zf: pcode::VarNode,
    pub sf: pcode::VarNode,
    pub of: pcode::VarNode,
    pub ie: pcode::VarNode,
    pub sr: pcode::VarNode,
}

impl StatusRegHandler {
    pub fn new(sleigh: &SleighData) -> Self {
        let r = |name: &str| sleigh.get_reg(name).unwrap().var;
        Self { cf: r("CF"), zf: r("ZF"), sf: r("SF"), of: r("OF"), ie: r("IE"), sr: r("SR") }
    }
}

impl crate::cpu::RegHandler for StatusRegHandler {
    fn read(&mut self, cpu: &mut Cpu) {
        let read_bit = |var: pcode::VarNode| (cpu.read_var::<u8>(var) as u32) & 0x1;

        let base_sr = cpu.read_var::<u32>(self.sr);

        let sr_flags = (read_bit(self.cf))
            | (read_bit(self.zf) << 1)
            | (read_bit(self.sf) << 2)
            | (read_bit(self.of) << 8)
            | (read_bit(self.ie) << 3);

        let sr = (base_sr & 0xfef0) | sr_flags;

        cpu.write_var::<u32>(self.sr, sr);
    }

    fn write(&mut self, cpu: &mut Cpu) {
        let sr = cpu.read_var::<u32>(self.sr);
        let extract_bit = |bit: u32| ((sr >> bit) & 0x1) as u8;

        cpu.write_var::<u8>(self.cf, extract_bit(0));
        cpu.write_var::<u8>(self.zf, extract_bit(1));
        cpu.write_var::<u8>(self.sf, extract_bit(2));
        cpu.write_var::<u8>(self.of, extract_bit(8));
        cpu.write_var::<u8>(self.ie, extract_bit(3));
    }
}
