//! Code for managing the emulator's code cache.

use ahash::{HashMap, HashSet};

#[derive(Copy, Clone, Debug, Default, Hash, PartialEq, Eq)]
pub struct BlockKey {
    pub vaddr: u64,
    pub isa_mode: u64,
}

impl BlockKey {
    pub fn with_vaddr(mut self, vaddr: u64) -> Self {
        self.vaddr = vaddr;
        self
    }
}

impl std::fmt::Display for BlockKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "[vaddr={:#x},mode={}]",
            self.vaddr, self.isa_mode
        ))
    }
}

/// Keeps track of all the code in the program that the emulator has discovered.
#[derive(Default)]
pub struct BlockTable {
    pub map: HashMap<BlockKey, super::BlockGroup>,
    pub blocks: Vec<super::Block>,
    pub disasm: HashMap<BlockKey, String>,
    pub breakpoints: HashSet<u64>,
    pub modified: HashSet<usize>,
}

impl BlockTable {
    pub fn flush_code(&mut self) {
        self.map.clear();
        self.blocks.clear();
        self.disasm.clear();
        self.modified.clear();
    }

    pub fn get_info(&self, key: BlockKey) -> Option<BlockInfoRef<'_>> {
        let group = *self.map.get(&key)?;
        Some(BlockInfoRef { group, code: self })
    }
}

pub struct BlockInfoRef<'a> {
    group: super::BlockGroup,
    code: &'a BlockTable,
}

impl<'a> BlockInfoRef<'a> {
    /// Return an iterator over all (instruction start, instruction len) pairs in the group.
    pub fn instructions(&self) -> impl Iterator<Item = (u64, u64)> + 'a {
        self.code.blocks[self.group.range()].iter().flat_map(|block| block.instructions())
    }

    /// Return the entry block
    pub fn entry_block(&self) -> &'a super::Block {
        &self.code.blocks[self.group.blocks.0]
    }

    /// Return an iterator over all blocks in the group
    pub fn blocks(&self) -> impl Iterator<Item = (usize, &'a super::Block)> + 'a {
        self.group.range().map(|i| (i, &self.code.blocks[i]))
    }
}
