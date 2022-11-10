use std::path::{Path, PathBuf};

use anyhow::Context;
use icicle_vm::{cpu::ExceptionCode, linux::TerminationReason, Vm, VmExit};

pub fn input_visitor(
    input_dir: &Path,
    mut handler: impl FnMut(PathBuf, Vec<u8>) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut paths = vec![];
    for entry in
        input_dir.read_dir().with_context(|| format!("failed to read: {}", input_dir.display()))?
    {
        let path = entry?.path();
        // Ignore no paths that are not files, and `README.txt` files (these added by AFL).
        if !path.is_file() || path.ends_with("README.txt") {
            continue;
        }
        paths.push(path);
    }

    paths.sort();

    for path in paths {
        let input = std::fs::read(&path)?;
        tracing::debug!("input={}", path.display());
        handler(path, input)?;
    }

    Ok(())
}

/// Convert an icicle exit code to a status value that AFL understands
pub fn get_afl_exit_code(vm: &mut Vm, exit: VmExit) -> u32 {
    const SIGILL: u32 = 4;
    const SIGKILL: u32 = 9;
    const SIGSEGV: u32 = 11;
    const SIGSTOP: u32 = 19;

    match exit {
        VmExit::Running => 0,
        VmExit::Halt => match icicle_vm::get_linux_termination_reason(vm) {
            Some(TerminationReason::Exit(_)) => 0,
            Some(TerminationReason::Killed(signal)) => signal as u32,
            None => 0,
        },
        VmExit::InstructionLimit | VmExit::Interrupted => {
            tracing::debug!("Instruction limit reached");
            SIGSTOP
        }
        VmExit::Deadlock => {
            tracing::debug!("Deadlock detected");
            SIGSTOP
        }
        VmExit::UnhandledException((code, _)) => {
            tracing::debug!("Unhandled exception: {:?}", code);
            match code {
                // Currently these error codes are used to indicate that the program has ran out of
                // fuzzing input for MMIO.
                ExceptionCode::ReadWatch | ExceptionCode::WriteWatch => 0,

                ExceptionCode::ReadUnmapped
                | ExceptionCode::ReadPerm
                | ExceptionCode::ReadUnaligned
                | ExceptionCode::ReadUninitialized
                | ExceptionCode::WriteUnmapped
                | ExceptionCode::WritePerm
                | ExceptionCode::WriteUnaligned
                | ExceptionCode::ExecViolation => SIGSEGV,

                ExceptionCode::OutOfMemory => SIGKILL,
                ExceptionCode::InvalidInstruction | ExceptionCode::InvalidTarget => SIGILL,

                _ => 999,
            }
        }
        _ => 999,
    }
}
