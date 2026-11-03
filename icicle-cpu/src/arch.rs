//! Code related to tracking architecture-specific information for the CPU.

use crate::Cpu;

#[derive(Clone)]
pub struct CallCov {
    /// Represents registers used for passing integers to functions, these will be chosen before
    /// parameters on the stack
    pub integers: Vec<pcode::VarNode>,

    /// Represents the register used for returning integer return values from functions.
    pub int_return: pcode::VarNode,

    /// The alignment of parameters passed on the stack,
    pub stack_align: u64,

    /// The offset (relative to the stack pointer) of the parameters on the stack.
    pub stack_offset: u64,
}

impl Default for CallCov {
    fn default() -> Self {
        Self { integers: vec![], int_return: pcode::VarNode::NONE, stack_align: 1, stack_offset: 0 }
    }
}

/// Encodes information about how data is represented for the current architecture.
#[derive(Clone, Copy, Debug)]
pub struct DataEncoding {
    pub arch: target_lexicon::Architecture,
    pub data_model: target_lexicon::CDataModel,
    pub endianness: target_lexicon::Endianness,
}

impl Default for DataEncoding {
    fn default() -> Self {
        Self {
            arch: target_lexicon::Architecture::Unknown,
            data_model: target_lexicon::CDataModel::LP64,
            endianness: target_lexicon::Endianness::Little,
        }
    }
}

impl DataEncoding {
    pub fn from_triple(triple: &target_lexicon::Triple) -> Option<Self> {
        let data_model = triple.data_model().ok()?;
        let endianness = triple.endianness().ok()?;
        Some(Self { arch: triple.architecture, data_model, endianness })
    }

    pub fn from_triple_with_fallback(triple: &target_lexicon::Triple) -> Self {
        if let Some(encoding) = Self::from_triple(triple) {
            return encoding;
        }
        tracing::debug!("Failed to extract data encoding from {triple}, using LP64 as fallback",);
        Self {
            arch: triple.architecture,
            data_model: target_lexicon::CDataModel::LP64,
            endianness: target_lexicon::Endianness::Little,
        }
    }
}

/// Architecture specific CPU state.
pub struct Arch {
    /// Target triple for the current architecture.
    pub triple: target_lexicon::Triple,

    /// Data encoding for the current architecture.
    ///
    /// Note: this can be directly derived from the target triple, but we keep around the extracted
    /// values since they are tiny, copyable, and allows us to set some defaults to avoid possible
    /// panics.
    pub encoding: DataEncoding,

    /// The VarNode that represents the program's instruction pointer / PC.
    pub reg_pc: pcode::VarNode,

    /// The VarNode that represents address of the next instruction. This is neccessary for
    /// handling instructions that resume on the next instruction (e.g. syscalls) in an
    /// architecture independent way.
    ///
    /// Note: guaranteed to be 64-bits, and is only set after certain instructions.
    pub reg_next_pc: pcode::VarNode,

    /// The VarNode that represents the program's stack pointer.
    pub reg_sp: pcode::VarNode,

    /// The VarNode that contains the program's decoding mode.
    pub reg_isa_mode: Option<pcode::VarNode>,

    /// Context values for the decoder when running in different ISA modes.
    pub isa_mode_context: Vec<u64>,

    /// Values to initialize registers with on reset.
    pub reg_init: Vec<(pcode::VarNode, u128)>,

    /// Registers that should be treated as temporaries.
    pub temporaries: Vec<pcode::VarId>,

    /// Registers that represent arguments for the current calling convention.
    pub call_cov: CallCov,

    /// The function to call when the VM boots.
    pub on_boot: fn(&mut Cpu, u64),

    /// The sleigh specification for the current architecture.
    pub sleigh: sleigh_runtime::SleighData,
}

impl Arch {
    /// A generic architecture used for testing.
    pub fn none() -> Self {
        let mut sleigh = sleigh_runtime::SleighData::default();
        sleigh.alignment = 1;
        sleigh.add_custom_reg("INVALID_VARNODE", 0);
        let reg_pc = sleigh.add_custom_reg("pc", 8).unwrap();
        let reg_next_pc = sleigh.add_custom_reg("next_pc", 8).unwrap();
        let reg_sp = sleigh.add_custom_reg("sp", 8).unwrap();

        sleigh.add_custom_reg("a", 8).unwrap();
        sleigh.add_custom_reg("b", 8).unwrap();
        sleigh.add_custom_reg("c", 8).unwrap();

        Self {
            triple: target_lexicon::Triple::unknown(),
            encoding: DataEncoding::default(),
            reg_pc,
            reg_next_pc,
            reg_sp,
            reg_isa_mode: None,
            isa_mode_context: vec![0],
            reg_init: vec![],
            temporaries: vec![],
            call_cov: CallCov::default(),
            on_boot: generic_on_boot,
            sleigh,
        }
    }

    /// Converts bytes read from memory to a pointer sized integer for the current architecture by
    /// zero extending and converting the endianness as necessary.
    #[inline]
    pub fn bytes_to_pointer<const N: usize>(&self, bytes: [u8; N]) -> u64 {
        let size = (self.reg_pc.size as usize).min(N);

        let mut buf = [0; 8];
        buf[..size].copy_from_slice(&bytes[..size]);

        match self.triple.endianness().unwrap() {
            target_lexicon::Endianness::Little => u64::from_le_bytes(buf),
            target_lexicon::Endianness::Big => u64::from_be_bytes(buf),
        }
    }
}

pub fn generic_on_boot(cpu: &mut Cpu, entry: u64) {
    cpu.reset();
    cpu.write_pc(entry);
}
