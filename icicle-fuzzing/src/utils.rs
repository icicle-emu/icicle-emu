use std::{
    path::{Path, PathBuf},
    time::{Instant, SystemTime},
};

use anyhow::Context;
use icicle_vm::{linux::TerminationReason, Vm, VmExit};

use crate::CrashKind;

pub fn input_visitor(
    input_dir: &Path,
    mut handler: impl FnMut(PathBuf, Vec<u8>) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut paths = vec![];
    for entry in
        input_dir.read_dir().with_context(|| format!("failed to read: {}", input_dir.display()))?
    {
        let path = entry?.path();
        // Ignore no paths that are not files, and `README.txt` files (these are added by AFL).
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
pub fn get_afl_exit_code(vm: &Vm, exit: VmExit) -> u32 {
    const SIGILL: u32 = 4;
    const SIGKILL: u32 = 9;
    const SIGSEGV: u32 = 11;
    const SIGSTOP: u32 = 19;

    match CrashKind::from(exit) {
        CrashKind::Halt => 0,
        CrashKind::Hang => SIGSTOP,
        CrashKind::OutOfMemory => SIGKILL,
        CrashKind::Killed => match vm
            .env_ref::<icicle_vm::linux::Kernel>()
            .and_then(|kernel| kernel.process.termination_reason)
        {
            Some(TerminationReason::Exit(_)) => 0,
            Some(TerminationReason::Killed(signal)) => signal as u32,
            None => 999,
        },
        CrashKind::Custom(_) => SIGILL,
        CrashKind::ExecViolation => SIGILL,
        CrashKind::ReadViolation(_) | CrashKind::WriteViolation(_) => SIGSEGV,
        CrashKind::Unknown => 999,
    }
}

pub struct BlockCoverageTracker {
    /// The blocks seen by the fuzzer. Index by the starting address of the block with the time and
    /// input ID corresponding to when the first input reaching that block was found.
    pub seen: indexmap::IndexMap<u64, (SystemTime, u64)>,

    /// The last internal block count seen by the tracker, used for avoiding a hash lookup when
    /// there is no coverage increase.
    seen_internal_blocks: usize,

    /// The system time at the time when the tracker was started.
    start: SystemTime,

    /// The last time we saved the coverage file.
    last_save: Instant,

    /// The number of blocks seen the last time the coverage file was saved.
    saved_seen_blocks: usize,
}

impl BlockCoverageTracker {
    pub fn new() -> Self {
        Self {
            seen: indexmap::IndexMap::new(),
            seen_internal_blocks: 0,
            start: SystemTime::now(),
            last_save: Instant::now(),
            saved_seen_blocks: 0,
        }
    }

    /// Add any new blocks in `code` to the set of seen blocks.
    pub fn add_new(&mut self, code: &icicle_vm::BlockTable, input_id: u64) -> bool {
        if code.blocks.len() <= self.seen_internal_blocks {
            return false;
        }
        let mut new = false;
        for block in &code.blocks[self.seen_internal_blocks..] {
            if let Some(entry) = block.entry {
                new |= self.add(entry, input_id);
            }
        }
        tracing::debug!("{} blocks found ({} internal blocks)", self.seen.len(), code.blocks.len());

        self.seen_internal_blocks = code.blocks.len();
        new
    }

    /// Adds the block starting at `block` to the set of seen blocks.
    pub fn add(&mut self, block: u64, input_id: u64) -> bool {
        match self.seen.entry(block) {
            indexmap::map::Entry::Occupied(_) => false,
            indexmap::map::Entry::Vacant(slot) => {
                let time = SystemTime::now();
                tracing::debug!("input={input_id} found new block: {:#x}", block);
                slot.insert((time, input_id));
                true
            }
        }
    }

    /// If there are any newly discovered blocks add sufficent time has passed since the last save,
    /// save the current set of seen blocks to `path`.
    pub fn maybe_save(&mut self, path: &Path) -> anyhow::Result<()> {
        if self.saved_seen_blocks < self.seen.len() && self.last_save.elapsed().as_secs() > 10 {
            self.save(path)?;
            self.saved_seen_blocks = self.seen.len();
            self.last_save = Instant::now();
        }
        Ok(())
    }

    /// Saves the current set of seen blocks to `path`.
    /// @todo? Could append instead.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        use std::io::Write;

        let mut file = std::io::BufWriter::new(std::fs::File::create(path).with_context(|| {
            format!("Error saving coverage file, failed to create: {}", path.display())
        })?);

        for (addr, (time, inputs)) in &self.seen {
            if let Ok(duration) = time.duration_since(self.start) {
                writeln!(file, "{addr:#x},{},{inputs}", duration.as_millis())?;
            }
        }

        Ok(())
    }

    /// Returns the number of seen blocks.
    pub fn total_seen(&self) -> usize {
        self.seen.len()
    }
}
