pub const PR_SET_PDEATHSIG: u64 = 1;
pub const PR_GET_PDEATHSIG: u64 = 2;

pub const PR_GET_DUMPABLE: u64 = 3;
pub const PR_SET_DUMPABLE: u64 = 4;

pub const PR_GET_UNALIGN: u64 = 5;
pub const PR_SET_UNALIGN: u64 = 6;

pub const PR_GET_KEEPCAPS: u64 = 7;
pub const PR_SET_KEEPCAPS: u64 = 8;

pub const PR_GET_FPEMU: u64 = 9;
pub const PR_SET_FPEMU: u64 = 10;

pub const PR_GET_FPEXC: u64 = 11;
pub const PR_SET_FPEXC: u64 = 12;

pub const PR_GET_TIMING: u64 = 13;
pub const PR_SET_TIMING: u64 = 14;

pub const PR_SET_NAME: u64 = 15;
pub const PR_GET_NAME: u64 = 16;

pub const PR_GET_ENDIAN: u64 = 19;
pub const PR_SET_ENDIAN: u64 = 20;

pub const PR_GET_SECCOMP: u64 = 21;
pub const PR_SET_SECCOMP: u64 = 22;

pub const PR_CAPBSET_READ: u64 = 23;
pub const PR_CAPBSET_DROP: u64 = 24;

pub const PR_GET_TSC: u64 = 25;
pub const PR_SET_TSC: u64 = 26;

pub const PR_GET_SECUREBITS: u64 = 27;
pub const PR_SET_SECUREBITS: u64 = 28;

pub const PR_SET_TIMERSLACK: u64 = 29;
pub const PR_GET_TIMERSLACK: u64 = 30;

pub const PR_TASK_PERF_EVENTS_DISABLE: u64 = 31;
pub const PR_TASK_PERF_EVENTS_ENABLE: u64 = 32;

pub const PR_MCE_KILL: u64 = 33;
pub const PR_MCE_KILL_GET: u64 = 34;

pub const PR_SET_MM: u64 = 35;
pub const PR_SET_PTRACER: u64 = 0x59616d61;

pub const PR_SET_CHILD_SUBREAPER: u64 = 36;
pub const PR_GET_CHILD_SUBREAPER: u64 = 37;

pub const PR_SET_NO_NEW_PRIVS: u64 = 38;
pub const PR_GET_NO_NEW_PRIVS: u64 = 39;

pub const PR_GET_TID_ADDRESS: u64 = 40;

pub const PR_SET_THP_DISABLE: u64 = 41;
pub const PR_GET_THP_DISABLE: u64 = 42;

pub const PR_MPX_ENABLE_MANAGEMENT: u64 = 43;
pub const PR_MPX_DISABLE_MANAGEMENT: u64 = 44;

/// This operation allows a user-space program to set the floating-point mode.
pub const PR_SET_FP_MODE: u64 = 45;

/// Gets the floating-point mode
pub const PR_GET_FP_MODE: u64 = 46;

/// On the MIPS architecture, user-space code can be built using an ABI which permits linking with
/// code that has more restrictive floating-point (FP) requirements.
pub mod fp_mode {
    /// 64b FP registers
    pub const FR: u64 = 1 << 0;

    /// 32b compatibility
    pub const FRE: u64 = 1 << 1;
}

pub const PR_CAP_AMBIENT: u64 = 47;

/// Set task vector length
pub const PR_SVE_SET_VL: u64 = 50;
/// Get task vector length
pub const PR_SVE_GET_VL: u64 = 51;

pub const PR_GET_SPECULATION_CTRL: u64 = 52;
pub const PR_SET_SPECULATION_CTRL: u64 = 53;

pub const PR_PAC_RESET_KEYS: u64 = 54;

pub const PR_SET_TAGGED_ADDR_CTRL: u64 = 55;
pub const PR_GET_TAGGED_ADDR_CTRL: u64 = 56;

pub const PR_SET_IO_FLUSHER: u64 = 57;
pub const PR_GET_IO_FLUSHER: u64 = 58;
