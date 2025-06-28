pub mod syscall;

mod auxv;
mod prctl;

pub use self::{auxv::*, prctl::*};

/// The file descriptor reserved for stdin
pub const STDIN_FD: u64 = 0;

/// The file descriptor reserved for stdout
pub const STDOUT_FD: u64 = 1;

/// The file descriptor reserved for stderr
pub const STDERR_FD: u64 = 2;

pub const PAGE_SIZE: u64 = 0x1000;

/// Converts from a linux `prot` value to an icicle `perm` value
pub fn perm_from_prot(prot: u64) -> u8 {
    use icicle_cpu::mem::perm;

    let mut perm = perm::NONE;

    if prot & mmem::PROT_READ != 0 {
        perm |= perm::READ;
    }
    if prot & mmem::PROT_WRITE != 0 {
        perm |= perm::WRITE;
    }
    if prot & mmem::PROT_EXEC != 0 {
        perm |= perm::EXEC;
    }

    perm
}

pub mod mmem {
    pub const PROT_READ: u64 = 0x1;
    pub const PROT_WRITE: u64 = 0x2;
    pub const PROT_EXEC: u64 = 0x4;
    pub const PROT_NONE: u64 = 0x0;

    /// Crate a shared mapping mapping. Changes made to this mapping are visible to any other
    /// processes mapping the same region
    ///
    /// NOTE: one of either `MAP_PRIVATE` or `MAP_SHARED` must be set
    pub const MAP_SHARED: u64 = 0x01;

    /// Crate a private copy-on-write mapping. Changes made to this mapping are not reflected in any
    /// other mapping to the same address
    ///
    /// NOTE: one of either `MAP_PRIVATE` or `MAP_SHARED` must be set
    pub const MAP_PRIVATE: u64 = 0x02;

    /// If this flag is set, the `addr` field of mmap is not treated as a hit
    pub const MAP_FIXED: u64 = 0x10;

    /// Avoid reserving swapspace for this mapping, since (in the emulator) we don't use swap space
    /// this flag does nothing
    pub const MAP_NORESERVE: u64 = 0x0400;

    /// If this flag is set the mapping is not backed by a file, and its contents are initialized
    /// to zero. `fd` argument is either ignore, or required to be `-1`.
    pub const MAP_ANONYMOUS: u64 = 0x0020;
    pub const MAP_ANONYMOUS_MIPS: u64 = 0x0800;

    pub const MREMAP_MAYMOVE: u64 = 0x1;
    pub const MREMAP_FIXED: u64 = 0x2;
    pub const MREMAP_DONTUNMAP: u64 = 0x4;
}

pub mod signal {
    pub const SIGABRT: u8 = 6;
    pub const SIGKILL: u8 = 9;
    pub const SIGSEGV: u8 = 11;
    pub const SIGALRM: u8 = 14;
    pub const SIGCHLD: u8 = 17;
}

pub mod poll {
    pub const POLLIN: u64 = 0x0001;
    pub const POLLPRI: u64 = 0x0002;
    pub const POLLOUT: u64 = 0x0004;
    pub const POLLERR: u64 = 0x0008;
    pub const POLLHUP: u64 = 0x0010;
    pub const POLLNVAL: u64 = 0x0020;
}
