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

    /// The VM was shutdown.
    Shutdown,

    /// Killed by an environment specific mechanism.
    Killed,

    /// A deadlock was detected.
    Deadlock,

    /// MMU was unable to allocate memory for an operation.
    OutOfMemory,

    /// Internal error where the emulator reached unimplemented code.
    Unimplemented,

    /// Some unknown error occurred.
    Unknown,

    /// Custom user-defined exit code. Never used by the emulator itself or any reusable components.
    Custom(u64),

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
            Self::Running => f.write_str("Running"),
            Self::InstructionLimit => f.write_str("InstructionLimit"),
            Self::Breakpoint => f.write_str("Breakpoint"),
            Self::Interrupted => f.write_str("Interrupt"),
            Self::Halt => f.write_str("Halt"),
            Self::Shutdown => f.write_str("Shutdown"),
            Self::Killed => f.write_str("Killed"),
            Self::Unimplemented => f.write_str("Unimplemented"),
            Self::Deadlock => f.write_str("Deadlock"),
            Self::OutOfMemory => f.write_str("OutOfMemory"),
            Self::Unknown => f.write_str("Unknown"),
            Self::Custom(code) => f.write_fmt(format_args!("Custom({code:#0x})")),
            Self::UnhandledException((ExceptionCode::InternalError, error)) => {
                f.write_fmt(format_args!("InternalError({error:?})"))
            }
            Self::UnhandledException((code, value)) => {
                f.write_fmt(format_args!("UnhandledException(code={code:?}, value={value:#0x})"))
            }
        }
    }
}
