use crate::ExceptionCode;

#[derive(PartialEq, Eq, Copy, Clone)]
pub enum VmExit {
    /// The VM is still running.
    Running,

    /// The VM exited because it reached instruction count limit.
    InstructionLimit,

    /// The VM exited because it reached a breakpoint.
    Breakpoint,

    /// The VM exited because the interrupt flag was set.
    Interrupted,

    /// The VM has halted.
    Halt,

    /// Killed by an environment specific mechanism.
    Killed,

    /// A deadlock was detected.
    Deadlock,

    /// MMU was unable to allocate memory for an operation.
    OutOfMemory,

    /// Internal error where the emulator reached unimplemented code.
    Unimplemented,

    /// The VM exited due to a unhandled exception.
    UnhandledException((ExceptionCode, u64)),
}

impl Default for VmExit {
    fn default() -> Self {
        Self::Running
    }
}

impl std::fmt::Debug for VmExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Running => write!(f, "Running"),
            Self::InstructionLimit => write!(f, "InstructionLimit"),
            Self::Breakpoint => write!(f, "Breakpoint"),
            Self::Interrupted => write!(f, "Interrupt"),
            Self::Halt => write!(f, "Halt"),
            Self::Killed => write!(f, "Killed"),
            Self::Unimplemented => write!(f, "Unimplemented"),
            Self::Deadlock => write!(f, "Deadlock"),
            Self::OutOfMemory => write!(f, "OutOfMemory"),
            Self::UnhandledException((code, value)) => {
                write!(f, "UnhandledException(code={code:?}, value={value:#0x})")
            }
        }
    }
}
