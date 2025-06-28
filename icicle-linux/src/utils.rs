use icicle_cpu::mem::MemResult;

use crate::LinuxMmu;

pub struct MemWriter {
    pub offset: u64,
    align_mask: u64,
}

impl MemWriter {
    pub fn new(offset: u64, alignment: u64) -> Self {
        assert_eq!(alignment.count_ones(), 1, "alignment must be a valid power of 2");
        Self { offset, align_mask: alignment - 1 }
    }

    pub fn write_bytes<M: LinuxMmu>(&mut self, mmu: &mut M, buf: &[u8]) -> MemResult<u64> {
        let vaddr = self.offset;
        mmu.write_bytes(vaddr, buf)?;

        self.offset += buf.len() as u64;

        let padding = ((self.align_mask + 1) - (self.offset & self.align_mask)) & self.align_mask;
        mmu.write_bytes(self.offset, &[0; 32][..padding as usize])?;

        self.offset += padding;

        Ok(vaddr)
    }
}
