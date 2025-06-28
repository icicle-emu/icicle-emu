//! Emulated user mode for linux
pub mod errno;
pub mod fs;
pub mod sys;
pub mod types;

mod arch;
mod utils;

use std::{
    any::Any,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
};

use bstr::ByteSlice;
use tracing::info;

use icicle_cpu::{
    debug_info::{DebugInfo, SourceLocation},
    elf::ElfLoader,
    mem::{self, perm, AllocLayout, Mapping, MemError, MemResult, VirtualMemoryMap},
    Exception, ExceptionCode, ValueSource, VmExit,
};

pub trait LinuxMmu {
    fn memmap(&mut self, start: u64, len: u64, mapping: Mapping) -> bool;
    fn unmap(&mut self, start: u64, len: u64) -> bool;
    fn next_free(&self, layout: AllocLayout) -> MemResult<u64>;
    fn alloc(&mut self, layout: AllocLayout, mapping: Mapping) -> MemResult<u64>;
    fn free(&mut self, start: u64, len: u64) -> bool;

    fn take_virtual_mapping(&mut self) -> VirtualMemoryMap;
    fn restore_virtual_mapping(&mut self, map: VirtualMemoryMap);

    fn read_bytes_raw(&mut self, addr: u64, buf: &mut [u8], perm: u8) -> MemResult<()>;
    fn read_bytes(&mut self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
        self.read_bytes_raw(addr, buf, perm::READ)
    }
    fn write_bytes_raw(&mut self, addr: u64, buf: &[u8], perm: u8) -> MemResult<()>;
    fn write_bytes(&mut self, addr: u64, buf: &[u8]) -> MemResult<()> {
        self.write_bytes_raw(addr, buf, perm::WRITE)
    }
    fn update_perm(&mut self, addr: u64, count: u64, perm: u8) -> MemResult<()>;
    fn fill(&mut self, addr: u64, len: u64, val: u8) -> MemResult<()>;

    // Hopefully we can get rid of these:
    fn alloc_physical(&mut self, pages: usize) -> MemResult<Vec<mem::physical::Index>>;
    fn get_physical_mut(&mut self, index: mem::physical::Index) -> &mut mem::physical::Page;
    fn map_physical(&mut self, addr: u64, id: mem::physical::Index) -> bool;
    fn move_region(&mut self, old_addr: u64, old_end: u64, new_addr: u64) -> MemResult<()>;
    fn get_perm(&self, addr: u64) -> u8;
    fn clone_virtual_map(&mut self) -> VirtualMemoryMap;
    fn snapshot_virtual_map(&mut self) -> VirtualMemoryMap;
}

impl LinuxMmu for mem::Mmu {
    fn memmap(&mut self, start: u64, len: u64, mapping: Mapping) -> bool {
        mem::Mmu::map_memory_len(self, start, len, mapping)
    }

    fn unmap(&mut self, start: u64, len: u64) -> bool {
        mem::Mmu::unmap_memory_len(self, start, len)
    }

    fn next_free(&self, layout: AllocLayout) -> MemResult<u64> {
        mem::Mmu::find_free_memory(self, layout)
    }

    fn alloc(&mut self, layout: AllocLayout, mapping: Mapping) -> MemResult<u64> {
        mem::Mmu::alloc_memory(self, layout, mapping)
    }

    fn free(&mut self, start: u64, len: u64) -> bool {
        mem::Mmu::unmap_memory_len(self, start, len)
    }

    fn take_virtual_mapping(&mut self) -> VirtualMemoryMap {
        mem::Mmu::take_virtual_mapping(self)
    }

    fn restore_virtual_mapping(&mut self, map: VirtualMemoryMap) {
        mem::Mmu::restore_virtual_mapping(self, map)
    }

    fn read_bytes_raw(&mut self, addr: u64, buf: &mut [u8], perm: u8) -> MemResult<()> {
        mem::Mmu::read_bytes(self, addr, buf, perm)
    }

    fn write_bytes_raw(&mut self, addr: u64, buf: &[u8], perm: u8) -> MemResult<()> {
        mem::Mmu::write_bytes(self, addr, buf, perm)
    }

    fn update_perm(&mut self, addr: u64, count: u64, perm: u8) -> MemResult<()> {
        mem::Mmu::update_perm(self, addr, count, perm)
    }

    fn fill(&mut self, addr: u64, len: u64, val: u8) -> MemResult<()> {
        mem::Mmu::fill_mem(self, addr, len, val)
    }

    fn alloc_physical(&mut self, pages: usize) -> MemResult<Vec<mem::physical::Index>> {
        mem::Mmu::alloc_physical(self, pages)
    }

    fn get_physical_mut(&mut self, index: mem::physical::Index) -> &mut mem::physical::Page {
        mem::Mmu::get_physical_mut(self, index)
    }

    fn map_physical(&mut self, addr: u64, id: mem::physical::Index) -> bool {
        mem::Mmu::map_physical(self, addr, id)
    }

    fn move_region(&mut self, old_addr: u64, size: u64, new_addr: u64) -> MemResult<()> {
        mem::Mmu::move_region_len(self, old_addr, size, new_addr)
    }

    fn get_perm(&self, addr: u64) -> u8 {
        mem::Mmu::get_perm(self, addr)
    }

    fn clone_virtual_map(&mut self) -> VirtualMemoryMap {
        self.mapping.clone()
    }

    fn snapshot_virtual_map(&mut self) -> VirtualMemoryMap {
        mem::Mmu::snapshot_virtual_mapping(self)
    }
}

pub trait LinuxCpu {
    type Mem: LinuxMmu;
    type CpuSnapshot;

    fn mem(&mut self) -> &mut Self::Mem;

    fn read_var(&self, var: pcode::VarNode) -> u64;
    fn write_var(&mut self, var: pcode::VarNode, val: u64);

    fn save_cpu_state(&mut self) -> Box<dyn Any>;

    fn restore_cpu_state(&mut self, state: &Box<dyn Any>);
    fn i_count(&self) -> u64;
    fn resume(&mut self);
    fn set_next_pc(&mut self, addr: u64);

    fn sleigh(&self) -> &sleigh_runtime::SleighData;
}

impl LinuxCpu for icicle_cpu::Cpu {
    type Mem = mem::Mmu;
    type CpuSnapshot = icicle_cpu::CpuSnapshot;

    fn mem(&mut self) -> &mut Self::Mem {
        &mut self.mem
    }

    fn read_var(&self, var: pcode::VarNode) -> u64 {
        ValueSource::read_dynamic(self, var.into()).zxt()
    }

    fn write_var(&mut self, var: pcode::VarNode, val: u64) {
        ValueSource::write_trunc(self, var, val)
    }

    fn save_cpu_state(&mut self) -> Box<dyn Any> {
        self.snapshot()
    }

    fn restore_cpu_state(&mut self, state: &Box<dyn Any>) {
        let snapshot = state.downcast_ref::<Self::CpuSnapshot>().unwrap();
        self.restore(snapshot);
    }

    fn i_count(&self) -> u64 {
        self.icount
    }

    fn resume(&mut self) {
        let next_pc = ValueSource::read_var(self, self.arch.reg_next_pc);
        self.exception = Exception::new(ExceptionCode::ExternalAddr, next_pc);
        self.set_next_pc(next_pc);
    }

    fn set_next_pc(&mut self, addr: u64) {
        ValueSource::write_var(self, self.arch.reg_next_pc, addr);
    }

    fn sleigh(&self) -> &sleigh_runtime::SleighData {
        &self.arch.sleigh
    }
}

#[derive(Debug, Clone, Copy)]
pub enum LinuxError {
    /// Represents a regular Linux error code returned to user space
    Error(u64),

    /// Represents a situation where the VM should exit.
    VmExit(VmExit),
}

impl From<u64> for LinuxError {
    fn from(value: u64) -> Self {
        if let Some(exception) = errno::vm_exit(value) {
            return Self::VmExit(exception);
        }
        Self::Error(value)
    }
}

impl From<VmExit> for LinuxError {
    fn from(value: VmExit) -> Self {
        Self::VmExit(value)
    }
}

impl From<MemError> for LinuxError {
    fn from(e: MemError) -> Self {
        match e {
            MemError::OutOfMemory => Self::Error(errno::ENOMEM),
            _ => Self::Error(errno::EFAULT),
        }
    }
}

pub type LinuxResult = Result<u64, LinuxError>;

#[derive(Clone, Default)]
pub struct Args {
    pub argv: Vec<Vec<u8>>,
    pub env: Vec<Vec<u8>>,
}

impl Args {
    pub fn set<BIN, ARG, KEY, VALUE>(&mut self, bin: BIN, argv: &[ARG], env: &[(KEY, VALUE)])
    where
        BIN: AsRef<[u8]>,
        ARG: AsRef<[u8]>,
        KEY: AsRef<[u8]>,
        VALUE: AsRef<[u8]>,
    {
        self.argv.clear();
        self.argv.push([bin.as_ref(), b"\0"].concat());
        for arg in argv {
            self.argv.push([arg.as_ref(), b"\0"].concat());
        }

        self.env.clear();
        for (key, value) in env {
            self.env.push([key.as_ref(), b"=", value.as_ref(), b"\0"].concat());
        }
    }
}

#[derive(Default, Copy, Clone)]
pub struct Thread {
    pub set_child_tid: u64,
    pub clear_child_tid: u64,
}

/// Information about how the binary has been loaded into memory
#[derive(Default, Clone, Copy, Debug)]
pub struct LoadedImage {
    /// Address reserved for 16 random values
    pub rand_ptr: u64,

    /// Pointer to the program header
    pub phdr_ptr: u64,

    // The number of entires in the program header
    pub phdr_num: u64,

    /// Pointer to program entrypoint
    pub entry_ptr: u64,

    /// Pointer to pathname used to execute the program
    pub pathname_ptr: u64,

    /// Pointer to platform name
    pub platform_ptr: u64,

    /// Pointer to the base address of the dynamic linker
    pub base_ptr: u64,

    /// The start address of the stack
    pub stack_start: u64,

    /// The starting address of the program break
    pub start_brk: u64,

    /// The current program break
    pub end_brk: u64,

    /// The offset this library was relocated from its base address
    // @fixme: currently this only keeps track of the root level library, we should consider
    // parsing this information from the link-map metadata directly in the loaded image.
    pub relocation_offset: u64,

    /// The start address of the original binary.
    pub start_addr: u64,

    /// The end address of the original binary.
    pub end_addr: u64,
}

/// Timer subsystem
#[derive(Default, Clone)]
pub struct Timer {
    /// The `i_count` when the `SIGALRM` signal should be delivered to the process
    pub alarm: Option<u64>,
}

/// Module for generating fake random numbers
pub struct Random {
    seed: u8,
}

impl Random {
    pub fn new(seed: u8) -> Self {
        Self { seed }
    }

    pub fn next(&mut self) -> u8 {
        let next = self.seed;
        self.seed = self.seed.wrapping_add(1);
        next
    }
}

#[derive(Clone)]
pub struct MemMappedFile {
    pub path: fs::Path,
    pub end: u64,
}

impl std::fmt::Debug for MemMappedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemMappedFile")
            .field("path", &self.path.as_bstr())
            .field("end", &self.end)
            .finish()
    }
}

#[derive(Copy, Clone, Debug)]
pub enum TerminationReason {
    /// The process exited normally.
    Exit(u64),

    /// The process was killed by a signal
    Killed(u64),
}

#[derive(Copy, Clone, Debug)]
pub enum PauseReason {
    /// The process is waiting for a file to become ready.
    WaitFile,

    /// The process is waiting for a child process to close
    WaitProcess,

    /// The process is waiting for a signal.
    WaitSignal,

    /// The process was suspended to run another task and is always ready to be resumed.
    Switched,
}

pub struct ParkedProcess {
    /// Metadata about the process
    pub process: Process,

    /// Virtual memory state of the parked process
    pub mem: VirtualMemoryMap,

    /// CPU state for the parked process
    pub cpu: Box<dyn Any>,

    /// The reason why the process was paused.
    pub pause_reason: PauseReason,
}

impl ParkedProcess {
    pub fn read_var_zxt(&self, var: pcode::VarNode) -> u64 {
        self.cpu
            .downcast_ref::<icicle_cpu::CpuSnapshot>()
            .unwrap()
            .regs
            .read_dynamic(var.into())
            .zxt()
    }
}

#[derive(Clone, Copy)]
pub enum WaitEvent {
    Process { pid: u64, status: u64 },
    File { fd: u64 },
}

#[derive(Clone, Default)]
pub struct SemaphoreSetUndo {
    /// The value that should be subtracted from each semaphore in the set when the process exits.
    pub semadj: Vec<i64>,
}

impl SemaphoreSetUndo {
    pub fn new(num_semaphores: usize) -> Self {
        Self { semadj: vec![0; num_semaphores] }
    }
}

#[derive(Clone, Default)]
pub struct ProcessIpc {
    /// Attached shared memory segments. Maps from virtual address for shmem ID.
    pub shmem: HashMap<u64, ShmemId>,

    /// Undo state for semaphores referenced by the process
    pub semaphore_undo: HashMap<SemaphoreSetId, SemaphoreSetUndo>,
}

#[derive(Clone, Default)]
pub struct Process {
    /// The current working directory
    pub working_dir: Option<fs::DirEntryRef>,

    /// The arguments (and environment variables) that the process was created with
    pub args: Args,

    /// Metadata about the process set by the loader
    pub image: LoadedImage,

    /// The table of files open by this process
    pub file_table: fs::FileTable,

    /// Timer subsystem for the process
    pub timer: Timer,

    /// The unique identifier associated with the process
    pub pid: u64,

    /// The ID of the user that owns this process
    pub uid: u64,

    /// The pid of the parent process (ppid).
    pub parent_pid: u64,

    /// The set of pending signals for the process.
    pub pending_signals: u64,

    /// The name of the process,
    pub name: [u8; 16],

    /// Keeps track of memory mapped files for debugging
    // @fixme: this is slightly broken due to unmap/remapping
    pub mapping: BTreeMap<u64, MemMappedFile>,

    /// Keeps track of IPC resources used by the current process
    pub ipc: ProcessIpc,

    /// Debug info for the process
    // @fixme: this should be process specific.
    // @fixme: we should handle dynamically linked libraries.
    pub debug_info: Option<DebugInfo>,

    /// Registered signal handlers for this process
    pub signal_handlers: SignalHandlerTable,

    /// Other processes that are listining to the status of this process.
    pub listeners: BTreeSet<u64>,

    /// Configures whether this process was paused at a syscall.
    pub pause_at_syscall: u64,

    /// Files that have changed status.
    // @fixme? How is this implemented in real systems, this seems fairly inefficent.
    pub file_events: Vec<u64>,

    /// Processes that have changed status
    pub process_events: Vec<(u64, TerminationReason)>,

    /// Timeout value for this process when parked.
    pub timeout: Option<std::time::Duration>,

    /// The reason why the process was terminated.
    pub termination_reason: Option<TerminationReason>,
}

impl Process {
    pub fn new() -> Self {
        Self { file_table: fs::FileTable::new(), pid: 3333, ..Self::default() }
    }

    pub fn cwd(&self) -> fs::DirEntryRef {
        self.working_dir.as_ref().unwrap().clone()
    }
}

const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;
const SIG_ERR: u64 = (-1_i64) as u64;

#[derive(Clone)]
pub struct SignalHandlerTable {
    pub entries: [types::Sigaction; 64],
}

impl Default for SignalHandlerTable {
    fn default() -> Self {
        Self { entries: [types::Sigaction::default(); 64] }
    }
}

impl SignalHandlerTable {
    fn get_action(&self, signal: u64) -> SignalAction {
        if signal as usize >= self.entries.len() {
            return SignalAction::Terminate;
        }

        let action = self.entries[signal as usize];
        match action.handler.value {
            SIG_DFL => SignalAction::get_default(signal as u8),
            SIG_IGN => SignalAction::Ignore,
            SIG_ERR => SignalAction::Terminate,
            _ => SignalAction::Handler(action),
        }
    }

    fn set_action(&mut self, signal: u64, action: types::Sigaction) {
        if signal as usize >= self.entries.len() {
            return;
        }
        self.entries[signal as usize] = action;
    }
}

enum SignalAction {
    Terminate,
    Ignore,
    Handler(types::Sigaction),
}

impl SignalAction {
    fn get_default(signal: u8) -> Self {
        match signal {
            sys::signal::SIGABRT => SignalAction::Terminate,
            sys::signal::SIGKILL => SignalAction::Terminate,
            sys::signal::SIGSEGV => SignalAction::Terminate,
            _ => SignalAction::Ignore,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CatchSyscalls {
    All,
    Filtered,
    None,
}

pub struct KernelState {
    /// The kernel's current time
    pub time: std::time::Duration,
}

pub struct ProcessManager {
    /// Keeps track of the next free PID.
    next_pid: u64,

    /// All inactive processes.
    pub parked: VecDeque<ParkedProcess>,

    /// Keeps track of the most recently suspended process.
    last_suspend: u64,

    /// Keeps track of the number of times the last process been suspended and resumed without any
    /// other event (used for detecting potential hangs).
    suspend_count: u64,

    /// Configures whether the emulator should skip forward in time to avoid sleeping.
    warp_time: bool,
}

impl ProcessManager {
    pub fn new(warp_time: bool) -> Self {
        Self {
            next_pid: 3334,
            parked: VecDeque::new(),
            last_suspend: 0,
            suspend_count: 0,
            warp_time,
        }
    }

    pub fn reset(&mut self) {
        self.next_pid = 3334;
        self.parked.clear();
    }

    pub fn next_free_pid(&mut self) -> u64 {
        self.next_pid += 1;
        self.next_pid - 1
    }

    pub fn suspend<C: LinuxCpu>(
        &mut self,
        cpu: &mut C,
        process: Process,
        pause_reason: PauseReason,
    ) {
        // tracing::trace!("Suspended process at: {:#0x}", cpu.shadow_stack);
        self.parked.push_back(ParkedProcess {
            mem: cpu.mem().take_virtual_mapping(),
            cpu: cpu.save_cpu_state(),
            process,
            pause_reason,
        })
    }

    /// Attempts to detect when the program has hung because a process is stuck in a wait loop.
    // @fixme: this currently uses a very basic heuristic, which is mainly good for catching
    // emulator bugs.
    fn detect_hang(&mut self, pid: u64) -> bool {
        if true {
            return false;
        }

        if self.last_suspend == pid {
            self.suspend_count += 1;
            if self.suspend_count > 10 {
                return true;
            }
        }
        else {
            self.suspend_count = 0;
            self.last_suspend = pid;
        }

        false
    }

    pub fn resume_next<C: LinuxCpu>(&mut self, cpu: &mut C) -> Option<Process> {
        let ready_task = self.ready_now().or_else(|| self.ready_timewarp())?;

        if self.detect_hang(self.parked[ready_task].process.pid) {
            return None;
        }

        self.parked.rotate_left(ready_task);
        let parked = self.parked.pop_front()?;

        cpu.mem().restore_virtual_mapping(parked.mem);
        cpu.restore_cpu_state(&parked.cpu);

        tracing::debug!("resumed pid={}", parked.process.pid);

        // @fixme: need some way of clearing this timer.
        // parked.process.timeout.take();

        Some(parked.process)
    }

    /// Find the first process that is ready now (i.e. without skipping forward in time).
    fn ready_now(&mut self) -> Option<usize> {
        self.parked.iter().position(|parked| {
            if parked.process.pending_signals != 0 {
                // Will always wake up if there is a signal pending.
                return true;
            }

            match parked.pause_reason {
                PauseReason::Switched => true,
                PauseReason::WaitSignal => false,
                PauseReason::WaitFile => !parked.process.file_events.is_empty(),
                PauseReason::WaitProcess => !parked.process.process_events.is_empty(),
            }
        })
    }

    /// Find the first process that is ready after skipping foward in time.
    fn ready_timewarp(&mut self) -> Option<usize> {
        let (index, parked) = self.parked.iter().enumerate().min_by(|a, b| {
            match (a.1.process.timeout, b.1.process.timeout) {
                (Some(a), Some(b)) => a.cmp(&b),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            }
        })?;

        let time = parked.process.timeout?;

        if !self.warp_time {
            tracing::info!("Sleeping for {:?}", time);
            std::thread::sleep(time);
        }

        Some(index)
    }

    pub fn get_mut(&mut self, pid: u64) -> Option<&mut ParkedProcess> {
        // @fixme: make this more efficient
        self.parked.iter_mut().find(|x| x.process.pid == pid)
    }

    pub fn file_ready_event(&mut self, pid: u64, fd: u64) {
        if let Some(parked) = self.get_mut(pid) {
            parked.process.file_events.push(fd);
        }
    }

    pub fn process_destroyed_event(
        &mut self,
        listener_pid: u64,
        child_pid: u64,
        reason: TerminationReason,
    ) {
        if let Some(parked) = self.get_mut(listener_pid) {
            parked.process.process_events.push((child_pid, reason));
            parked.process.pending_signals |= 1 << (sys::signal::SIGCHLD - 1);
        }
    }
}

pub type ShmemId = u64;

#[derive(Default, Clone)]
pub struct Shmem {
    pub physical_pages: Vec<mem::physical::Index>,
    /// Ownership and permissions.
    pub perm: IpcPerm,
    /// The PID of the process that created the shm segmenet
    pub cpid: u64,
    /// The PID of last process that executed either shmat or shmdt on the shm segment.
    pub lpid: u64,
    /// The number of times the shared memory region has been attached.
    pub nattach: u64,
    /// Whether this shared memory region should be destroyed when `nattach == 0`
    pub destroy: bool,
}

impl Shmem {
    pub fn new(mem: Vec<mem::physical::Index>) -> Self {
        Self {
            physical_pages: mem,
            perm: IpcPerm::default(),
            cpid: 0,
            lpid: 0,
            nattach: 0,
            destroy: false,
        }
    }
}

#[derive(Default, Clone)]
pub struct IpcPerm {
    /// The key associated with the IPC resource.
    pub key: u64,

    /// Effective UID of the owner.
    pub uid: u64,

    /// Effective GID of the owner.
    pub gid: u64,

    /// Effective UID of the creator.
    pub cuid: u64,

    /// Effective GID of the owner.
    pub cgid: u64,

    /// Permissions and flags
    pub mode: u64,
}

pub type SemaphoreSetId = u64;

#[derive(Default, Clone)]
pub struct Semaphore {
    pub semval: u64,
    pub semzcnt: u64,
    pub semncnt: u64,
    pub sempid: u64,
}

#[derive(Default, Clone)]
pub struct SemaphoreSet {
    pub perm: IpcPerm,
    pub semaphores: Vec<Semaphore>,
}

impl SemaphoreSet {
    pub fn new(n_sems: usize) -> Self {
        Self { perm: IpcPerm::default(), semaphores: vec![Semaphore::default(); n_sems] }
    }
}

// @fixme: Currently we just use the IPC key as the ID for each resource, however Linux uses
// mantains a separate ID value. This may need to be updated to handle `IPC_PRIVATE`
#[derive(Default, Clone)]
pub struct Ipc {
    pub shmem: HashMap<ShmemId, Shmem>,
    pub semaphore_sets: HashMap<SemaphoreSetId, SemaphoreSet>,
}

impl Ipc {
    pub fn maybe_destroy_shmem<M: LinuxMmu>(&mut self, mem: &mut M, id: ShmemId) {
        let shmem = &self.shmem[&id];
        if shmem.destroy && shmem.nattach == 0 {
            self.destroy_shmem(mem, id);
        }
    }

    pub fn destroy_shmem<M: LinuxMmu>(&mut self, _mem: &mut M, id: ShmemId) {
        let shmem = self
            .shmem
            .remove(&id)
            .expect("[kernel]: attempted to destroy shmem that does not exist.");
        assert_eq!(shmem.nattach, 0, "[kernel]: attempted to destroy attached shmem segement.")

        // @fixme: free physical memory associated with this segment.
    }

    pub fn destroy_semset(&mut self, id: SemaphoreSetId) -> Result<(), u64> {
        self.semaphore_sets.remove(&id).ok_or(errno::EINVAL)?;
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct CloneState {
    /// Configures what parts of the process will be cloned.
    pub flags: sys::syscall::clone::Flags,

    /// Value to modify the stack pointer to in the child.
    pub new_sp: u64,

    /// Location to write the PID of the child in the parent.
    pub parent_tidptr: u64,

    /// Location to write the PID of the parent in the child.
    pub child_tidptr: u64,

    /// The value to update the TLS pointer to.
    pub tls_ptr: u64,
}

#[derive(Clone)]
pub struct KernelConfig {
    pub zero_stack: bool,
    pub force_mremap_move: bool,
    pub max_alloc_size: Option<u64>,
    pub kill_on_alloc_failure: bool,
    pub force_small_address_space: bool,
    pub boot_time: std::time::Duration,
}

impl Default for KernelConfig {
    fn default() -> Self {
        Self {
            zero_stack: true,
            force_mremap_move: true,
            max_alloc_size: None,
            force_small_address_space: false,
            kill_on_alloc_failure: false,
            boot_time: std::time::Duration::new(1600000000, 0),
        }
    }
}

pub struct Kernel {
    /// Architecture abstraction layer for the kernel
    pub arch: arch::KernelArch,

    /// Configures whether we should fill the stack with `0x00` at load-time.
    pub zero_stack: bool,

    /// Configures whether we should force memory to be moved when mmremap is called. This is
    /// useful for finding crashes that occur due during reallocations.
    pub force_mremap_move: bool,

    /// Sets the maximum size of a single mmap request.
    // @todo: revisit this.
    pub max_alloc_size: u64,

    /// Configures whether we should kill the process if exceed the maximum allocation size.
    pub kill_on_alloc_failure: bool,

    /// Configures the starting address for memory mappings
    pub mmap_start_addr: u64,

    /// Configures the addres `brk` is initialized at.
    pub brk_start_addr: u64,

    /// Includes the current `i_count` in syscall debugging.
    pub trace_i_count: bool,

    /// Temporary storage used for copying bytes from userspace into
    pub buffer: Vec<u8>,

    /// System call breakpoints
    pub syscall_breakpoints: HashSet<u64>,

    /// Whether syscall catching is enabled or not
    pub catch_syscalls: CatchSyscalls,

    /// Whether we caught a syscall at the current entry.
    pub did_break_at_entry: bool,

    //---
    // Move everything below this point to state struct
    //---
    /// Structure used for fork/clone
    pub clone_state: CloneState,

    /// Ipc structures potentially shared between processes.
    pub ipc: Ipc,

    /// Kernel random number source
    pub random: Random,

    /// The kernel's current time
    pub current_time: std::time::Duration,

    /// The hostname set for the system
    pub hostname: Vec<u8>,

    /// The active process
    pub process: Process,

    /// Processes managed by the kernel.
    pub process_manager: ProcessManager,

    /// The subsystem responsible for managing the virtual file system
    pub vfs: fs::VfsRoot,
}

impl Kernel {
    pub fn new(arch: &icicle_cpu::Arch, config: &KernelConfig) -> Self {
        let arch = arch::KernelArch::new(arch);

        let large_addr_space = !config.force_small_address_space
            && arch.libc(0).data_model.pointer_width().bytes() > 4;

        let mmap_start_addr =
            if large_addr_space { 0x0000_0008_0000_0000 } else { 0x0000_0000_0800_0000 };

        let brk_start_addr =
            if large_addr_space { 0x0000_0004_0000_0000 } else { 0x0000_0000_0400_0000 };

        let max_alloc_size =
            config.max_alloc_size.unwrap_or(if large_addr_space { 1 << 38 } else { 1 << 31 });

        Self {
            arch,

            zero_stack: config.zero_stack,
            force_mremap_move: config.force_mremap_move,
            kill_on_alloc_failure: config.kill_on_alloc_failure,
            max_alloc_size,
            mmap_start_addr,
            brk_start_addr,

            trace_i_count: true,
            buffer: vec![],

            random: Random::new(4),
            current_time: config.boot_time,
            syscall_breakpoints: HashSet::new(),
            catch_syscalls: CatchSyscalls::None,
            did_break_at_entry: false,

            hostname: b"Icicle-VM-0001\0".to_vec(),

            process: Process::new(),
            process_manager: ProcessManager::new(false),
            ipc: Ipc::default(),

            vfs: fs::VfsRoot::new(),

            clone_state: CloneState::default(),
        }
    }

    pub fn init_vfs(&mut self, sysroot: std::path::PathBuf) -> Result<(), String> {
        let mut vfs_path = sysroot;
        if vfs_path.ends_with("{arch}") {
            vfs_path.pop();
            vfs_path.push(self.arch.triple.architecture.to_string())
        }

        tracing::info!("Initializing VFS with rootfs: {}", vfs_path.display());
        self.vfs
            .init_default(vfs_path.clone())
            .map_err(|e| format!("Failed to load VFS: {e} ({})", vfs_path.display()))
    }

    pub fn mount_stddev<T, U>(
        &mut self,
        stdout: T,
        stderr: U,
        stddev_block_size: Option<u64>,
    ) -> Result<(), String>
    where
        T: fs::devices::Device + 'static,
        U: fs::devices::Device + 'static,
    {
        use fs::devices::ReadOnlyDevice;

        macro_rules! create_dev {
            ($path:expr, $dev:expr) => {
                let dev = self.vfs.create_dev($path, $dev).map_err(|e| {
                    format!("failed to create: '{}': {e}", std::str::from_utf8($path).unwrap())
                })?;

                if let Some(size) = stddev_block_size {
                    fs::with_inode_mut(&dev.borrow().inode, |inode| {
                        inode.block_size = size;
                        Ok(())
                    })
                    .unwrap();
                }
            };
        }

        create_dev!(b"/dev/stdin", ReadOnlyDevice(std::io::stdin()));
        create_dev!(b"/dev/stdout", stdout);
        create_dev!(b"/dev/stderr", stderr);

        Ok(())
    }

    /// Allocate a region of memory with the specified permissions, returning the start address of
    /// the newly allocated region
    pub fn alloc<M>(&mut self, mem: &mut M, layout: AllocLayout, perm: u8) -> MemResult<u64>
    where
        M: LinuxMmu,
    {
        if layout.size > self.max_alloc_size {
            if self.kill_on_alloc_failure {
                self.process.pending_signals |= 1 << (sys::signal::SIGSEGV - 1);
            }
            return Err(MemError::OutOfMemory);
        }
        mem.alloc(layout, Mapping { perm, value: 0xAA })
    }

    /// Allocate a region of memory requiring it to start at `start_addr`.
    pub fn alloc_fixed<M>(
        &mut self,
        mem: &mut M,
        start_addr: u64,
        size: u64,
        perm: u8,
    ) -> MemResult<()>
    where
        M: LinuxMmu,
    {
        let layout = AllocLayout { addr: Some(start_addr), size, align: sys::PAGE_SIZE };
        if layout.size > self.max_alloc_size {
            if self.kill_on_alloc_failure {
                self.process.pending_signals |= 1 << (sys::signal::SIGSEGV - 1);
            }
            return Err(MemError::OutOfMemory);
        }
        if mem.next_free(layout)? != start_addr {
            return Err(MemError::Unmapped);
        }
        mem.alloc(layout, Mapping { perm, value: 0xAA })?;
        Ok(())
    }

    pub fn find_free<M>(&mut self, mem: &mut M, size: u64) -> MemResult<u64>
    where
        M: LinuxMmu,
    {
        let mut layout = AllocLayout {
            addr: Some(self.mmap_start_addr),
            size,
            align: u64::max(size.next_power_of_two(), sys::PAGE_SIZE),
        };

        // Try with excess alignment so that addresses are nicely aligned.
        if let Ok(free) = mem.next_free(layout) {
            return Ok(free);
        }

        // Use minimum alignment
        layout.align = sys::PAGE_SIZE;
        mem.next_free(layout)
    }

    /// Free a region of memory
    pub fn free<M>(&mut self, mem: &mut M, start: u64, len: u64) -> MemResult<()>
    where
        M: LinuxMmu,
    {
        match mem.free(start, len) {
            true => Ok(()),
            false => Err(MemError::Unmapped),
        }
    }

    /// Spawn a new process
    pub fn spawn<C: LinuxCpu>(&mut self, cpu: &mut C, pathname: &[u8]) -> Result<(), MemError> {
        const STACK_SIZE: u64 = 1 << 20;

        info!("Initialize vDSO");
        self.arch.dynamic.init_vdso(cpu)?;

        info!("Allocating stack space");
        let stack_end = self.alloc(
            cpu.mem(),
            AllocLayout { addr: Some(0x100_0000), size: STACK_SIZE, align: sys::PAGE_SIZE },
            perm::READ | perm::WRITE,
        )?;
        let stack_start = stack_end + STACK_SIZE;
        cpu.write_var(self.arch.reg_sp, stack_start);
        self.process.image.stack_start = stack_start;

        if self.zero_stack {
            cpu.mem().fill(stack_end, STACK_SIZE, 0x0)?;
        }

        self.process
            .mapping
            .insert(stack_end, MemMappedFile { path: b"(stack)".to_vec(), end: stack_start });

        info!("Setting brk");
        let layout =
            AllocLayout { addr: Some(self.brk_start_addr), size: 0x1_0000, align: sys::PAGE_SIZE };
        self.process.image.start_brk = cpu.mem().next_free(layout)?;
        self.process.image.end_brk = self.process.image.start_brk;

        self.process.mapping.insert(self.process.image.start_brk, MemMappedFile {
            path: b"(brk)".to_vec(),
            end: self.process.image.end_brk,
        });

        // Allocate 4 KB space for args and environment variables
        info!("Allocating args and env");
        let arg_start = self.alloc(
            cpu.mem(),
            AllocLayout::from_size_align(sys::PAGE_SIZE, sys::PAGE_SIZE),
            perm::READ | perm::WRITE,
        )?;

        let mut writer = utils::MemWriter::new(arg_start, 8);

        // Dummy random values, so emulation is deterministic
        self.process.image.rand_ptr = writer.write_bytes(cpu.mem(), &[0x33; 16][..])?;

        // Write path and platform name
        let pathname = pathname.iter().copied().chain(std::iter::once(0)).collect::<Vec<_>>();
        self.process.image.pathname_ptr = writer.write_bytes(cpu.mem(), &pathname)?;
        self.process.image.platform_ptr =
            writer.write_bytes(cpu.mem(), &self.arch.platform_name)?;

        let mut auxv = vec![];
        sys::setup_auxv(&self.arch.triple, &self.process.image, &mut auxv);
        let mut stack_ptr = self.arch.push_bytes(cpu, &auxv)?;
        info!("Initialized auxv @ {:#0x}: {:#0x?}", stack_ptr, self.process.image);

        // Initialize env
        stack_ptr = self.arch.push_ptr(cpu, 0x0)?;
        for env in self.process.args.env.iter().rev() {
            let ptr = writer.write_bytes(cpu.mem(), env)?;
            info!("[{:#0x}] env: {:?}", ptr, env.as_bstr());
            stack_ptr = self.arch.push_ptr(cpu, ptr)?;
        }
        info!("Initialized envp @ {:#0x}", stack_ptr);

        // Initialize args
        stack_ptr = self.arch.push_ptr(cpu, 0x0)?;
        for arg in self.process.args.argv.iter().rev() {
            let ptr = writer.write_bytes(cpu.mem(), arg)?;
            info!("[{:#0x}] arg: {:?}", ptr, arg.as_bstr());
            stack_ptr = self.arch.push_ptr(cpu, ptr)?;
        }
        info!("Initialized argv @ {:#0x}", stack_ptr);

        self.process
            .mapping
            .insert(arg_start, MemMappedFile { path: b"(environ)".to_vec(), end: writer.offset });

        info!("(environ): {:#0x?}", arg_start..writer.offset);

        let argc = self.process.args.argv.len();
        // FIXME: should this be a `int` sized value instead?
        self.arch.push_ptr(cpu, argc as u64)?;

        info!("Initializing file system");
        if self.process.working_dir.is_none() {
            self.process.working_dir = Some(self.vfs.root.clone());
        }

        let mut try_open = |fd, path: &[u8]| {
            if let Ok(file) = self.vfs.open(path, fs::OpenFlags::empty()) {
                self.process.file_table.set(&mut self.process_manager, fd, file);
            }
        };

        try_open(sys::STDIN_FD, b"/dev/stdin");
        try_open(sys::STDOUT_FD, b"/dev/stdout");
        try_open(sys::STDERR_FD, b"/dev/stderr");

        Ok(())
    }

    pub(crate) fn get_file(&mut self, fd: u64) -> fs::Result<fs::ActiveFile> {
        self.process.file_table.get(&mut self.process_manager, fd)
    }

    fn fork<C: LinuxCpu>(&mut self, cpu: &mut C) -> LinuxResult {
        let child_pid = self.process_manager.next_free_pid();
        // cpu.set_instr_ptr(cpu.next_instruction);

        let is_thread = self.clone_state.flags.contains(sys::syscall::clone::Flags::VM);
        let child_mem = if is_thread {
            // @fixme: need to ensure that changes to the mapping are shared.
            cpu.mem().clone_virtual_map()
        }
        else {
            cpu.mem().snapshot_virtual_map()
        };

        // Return value for the parent process is the process id of the child
        self.arch.dynamic.set_result(cpu, child_pid);
        let parent = self.process.clone();
        self.process_manager.suspend(cpu, parent, PauseReason::Switched);

        tracing::debug!("new process spawned pid={}", child_pid);
        cpu.mem().restore_virtual_mapping(child_mem);
        self.process.parent_pid = self.process.pid;
        self.process.pid = child_pid;
        self.process.listeners.clear();
        self.process.listeners.insert(self.process.parent_pid);

        if self.clone_state.new_sp != 0 {
            cpu.write_var(self.arch.reg_sp, self.clone_state.new_sp);
        }

        // Return value for the child process is always 0
        Ok(0)
    }

    /// Parks the current process and resumes a pending one.
    fn switch_task<C: LinuxCpu>(&mut self, cpu: &mut C, reason: PauseReason) -> LinuxResult {
        self.process_manager.suspend(cpu, std::mem::take(&mut self.process), reason);

        match self.process_manager.resume_next(cpu) {
            Some(process) => {
                self.process = process;
                Ok(0)
            }
            None => Err(VmExit::Halt.into()),
        }
    }

    fn destroy_process<C: LinuxCpu>(
        &mut self,
        cpu: &mut C,
        reason: TerminationReason,
    ) -> Option<VmExit> {
        self.process.termination_reason = Some(reason);
        let pid = self.process.pid;

        if self.process.parent_pid == 0 {
            tracing::info!("root process {pid} terminated: {reason:?}");
            // This is the root level process, so fully exit.
            return match reason {
                TerminationReason::Exit(_) => Some(VmExit::Halt),
                TerminationReason::Killed(_) => Some(VmExit::Killed),
            };
        }

        // Undo any semaphore events
        for (set_id, entry) in self.process.ipc.semaphore_undo.drain() {
            let set = self.ipc.semaphore_sets.get_mut(&set_id).expect("semaphore set missing");
            for (semaphore, semadj) in set.semaphores.iter_mut().zip(entry.semadj) {
                semaphore.semval = (semaphore.semval as i64 - semadj) as u64;
            }
        }

        // @fixme: update parent pid of all child processes

        for listener_pid in &self.process.listeners {
            self.process_manager.process_destroyed_event(*listener_pid, pid, reason);
        }

        match self.process_manager.resume_next(cpu) {
            Some(process) => {
                self.process = process;
                None
            }
            None => Some(VmExit::Deadlock),
        }
    }

    /// Remove the lowest pending signal, and run the appropriate signal handler
    fn handle_pending_signal<C: LinuxCpu>(&mut self, cpu: &mut C) -> Option<VmExit> {
        if self.process.pending_signals == 0 {
            return None;
        }

        // Find the lowest pending signal and pop it.
        let signal_idx = self.process.pending_signals.trailing_zeros() as u64;
        self.process.pending_signals &= !(1 << signal_idx);
        let signal = signal_idx + 1;

        match self.process.signal_handlers.get_action(signal) {
            SignalAction::Ignore => None,
            SignalAction::Terminate => self.destroy_process(cpu, TerminationReason::Killed(signal)),
            SignalAction::Handler(action) => {
                if let Err(_) = self.arch.dynamic.setup_signal_frame(cpu, signal, &action) {
                    return self.destroy_process(
                        cpu,
                        TerminationReason::Killed(sys::signal::SIGSEGV as u64),
                    );
                }
                cpu.set_next_pc(action.handler.value);
                None
            }
        }
    }

    pub fn init_ipc_perm(&self, key: u64, flags: u64) -> IpcPerm {
        let uid = self.process.uid;
        IpcPerm { key, uid, gid: uid, cuid: uid, cgid: uid, mode: flags & 0b111111111 }
    }

    pub fn handle_syscall<C: LinuxCpu>(&mut self, cpu: &mut C) -> Option<VmExit> {
        let id = self.arch.get_syscall_id(cpu) as u64;

        if !std::mem::take(&mut self.did_break_at_entry) && self.catch_syscall(id) {
            self.did_break_at_entry = true;
            return Some(VmExit::Breakpoint);
        }

        self.buffer.clear();
        match sys::syscall::handle_syscall(self, cpu, id) {
            Ok(value) => self.arch.dynamic.set_result(cpu, value),
            Err(LinuxError::Error(error)) => self.arch.dynamic.set_error(cpu, error),
            Err(LinuxError::VmExit(exit)) => return Some(exit),
        }

        // @fixme: this is used for tracking resumption from syscalls from timeouts, but this should
        // be handled better.
        self.process.timeout.take();

        if let Some(exit) = self.handle_pending_signal(cpu) {
            return Some(exit);
        }
        cpu.resume();

        match self.catch_syscall(id) {
            true => Some(VmExit::Breakpoint),
            false => None,
        }
    }

    fn catch_syscall(&mut self, id: u64) -> bool {
        match self.catch_syscalls {
            CatchSyscalls::All => true,
            CatchSyscalls::Filtered => self.syscall_breakpoints.contains(&id),
            CatchSyscalls::None => false,
        }
    }

    /// Update the state of all kernel timers
    fn tick<C: LinuxCpu>(&mut self, cpu: &mut C) {
        if let Some(alarm_timeout) = self.process.timer.alarm {
            if cpu.i_count() > alarm_timeout {
                self.process.timer.alarm = None;
            }
        }
    }

    pub fn set_env(&mut self, args: &[Vec<u8>], env: &[Vec<u8>]) {
        self.process.args.argv.clear();
        self.process.args.argv.extend_from_slice(args);

        self.process.args.env.clear();
        self.process.args.env.extend_from_slice(env);
    }

    pub fn find_containing_library<M>(&self, mem: &mut M, addr: u64) -> Option<LinkMapEntry>
    where
        M: LinuxMmu,
    {
        let mut best: Option<LinkMapEntry> = None;
        let link_map_addr = self.find_link_map(mem)?;

        for (_, entry) in self.read_link_map(mem, link_map_addr) {
            // @fixme: check the length of library instead of just picking the closest library.
            if entry.l_addr < addr && best.map_or(true, |best| best.l_addr < entry.l_addr) {
                best = Some(entry)
            }
        }

        best
    }

    /// Attempts to resolve the address to the start of the link map
    pub fn find_link_map<M: LinuxMmu>(&self, mem: &mut M) -> Option<u64> {
        let debug_info = self.process.debug_info.as_ref()?;

        let r_debug_addr = match debug_info.r_debug_addr {
            Some(addr) => addr,
            None => self.arch.libc(debug_info.dl_debug_addr?).read::<arch::Ptr, _>(mem).ok()?,
        };

        if r_debug_addr == 0 {
            return None;
        }

        let mut r_debug = self.arch.libc(r_debug_addr);
        let r_version = r_debug.read::<arch::UInt, _>(mem).ok()?;
        if r_version != 1 {
            tracing::warn!("Unknown version for `struct r_debug`: {} (expected 1)", r_version);
            return None;
        }

        r_debug.read::<arch::Ptr, _>(mem).ok()
    }

    pub fn read_link_map<'a, M: LinuxMmu>(
        &'a self,
        mem: &'a mut M,
        addr: u64,
    ) -> LinkMapIter<'a, M> {
        LinkMapIter { arch: &self.arch, mem, next: addr }
    }

    pub fn read_library_name<C>(
        &self,
        mem: &mut C,
        lib: LinkMapEntry,
        buf: &mut Vec<u8>,
    ) -> MemResult<()>
    where
        C: LinuxMmu,
    {
        let name = self.arch.libc(lib.l_name).read_cstr(mem, buf)?;
        // `l_name` is an empty string for the main executable.
        if name.is_empty() {
            self.arch.libc(self.process.image.pathname_ptr).read_cstr(mem, buf)?;
        }
        Ok(())
    }

    pub fn reset(&mut self) {
        let old_work_dir = self.process.working_dir.clone();
        self.process_manager.reset();

        self.buffer.clear();
        self.random = Random::new(4);
        self.current_time = std::time::Duration::new(1600000000, 0);

        // @fixme: eventually handle resetting the VFS.
        // self.vfs.reset();

        self.process.working_dir = old_work_dir;
    }

    pub fn toggle_breakpoint(&mut self, name: &str) {
        let syscall = match self.arch.dynamic.syscall_names().iter().position(|x| *x == name) {
            Some(index) => index as u64,
            None => {
                tracing::error!("Unknown syscall: {}", name);
                return;
            }
        };
        if self.syscall_breakpoints.insert(syscall) {
            info!("breakpoint set: {:?}", syscall)
        }
        else {
            self.syscall_breakpoints.remove(&syscall);
            info!("breakpoint removed: {:?}", syscall);
        }

        match self.syscall_breakpoints.is_empty() {
            true => self.catch_syscalls = CatchSyscalls::None,
            false => self.catch_syscalls = CatchSyscalls::Filtered,
        }
    }
}

impl ElfLoader for Kernel {
    fn read_file(&mut self, path: &[u8]) -> Result<Vec<u8>, String> {
        tracing::info!("loading: {}", path.escape_ascii());
        self.vfs
            .read_raw(path)
            .map_err(|e| format!("Error loading {}: {e:#0x}", path.escape_ascii()))
    }
}

impl icicle_cpu::Environment for Kernel {
    fn load(&mut self, cpu: &mut icicle_cpu::Cpu, path: &[u8]) -> Result<(), String> {
        tracing::info!("Clearing memory");
        cpu.mem.reset_virtual();
        cpu.reset();

        self.process.mapping.clear();

        tracing::info!("Reserving null page");
        cpu.mem.map_memory_len(0x0, sys::PAGE_SIZE, Mapping { perm: perm::NONE, value: 0xAA });
        self.process
            .mapping
            .insert(0x0, MemMappedFile { path: b"(null page)".to_vec(), end: sys::PAGE_SIZE });

        let metadata = self.load_elf(cpu, path)?;

        // Keep track of data we just mapped from the ELF file.
        self.process.mapping.insert(metadata.binary.base_ptr, MemMappedFile {
            path: path.to_vec(),
            end: metadata.binary.base_ptr + metadata.binary.length,
        });
        if let Some(interpreter) = metadata.interpreter.as_ref() {
            self.process.mapping.insert(interpreter.base_ptr, MemMappedFile {
                path: metadata.debug_info.dynamic_linker.clone(),
                end: interpreter.base_ptr + interpreter.length,
            });
        }

        self.process.debug_info = Some(metadata.debug_info);

        let base_ptr =
            metadata.interpreter.as_ref().map_or(metadata.binary.base_ptr, |x| x.base_ptr);

        self.process.image.base_ptr = base_ptr;
        self.process.image.phdr_ptr = metadata.binary.phdr_ptr;
        self.process.image.phdr_num = metadata.binary.phdr_num;
        self.process.image.entry_ptr = metadata.binary.entry_ptr;
        self.process.image.relocation_offset = metadata.binary.offset;
        self.process.image.start_addr = metadata.binary.base_ptr;
        self.process.image.end_addr = metadata.binary.base_ptr + metadata.binary.length;

        let entry =
            metadata.interpreter.as_ref().map_or(metadata.binary.entry_ptr, |x| x.entry_ptr);

        tracing::info!("Setting instruction pointer to: {entry:#0x}");
        (cpu.arch.on_boot)(cpu, entry);

        self.spawn(cpu, path).map_err(|e| format!("Failed to initialize environment: {e}"))?;

        Ok(())
    }

    fn handle_exception(&mut self, cpu: &mut icicle_cpu::Cpu) -> Option<VmExit> {
        self.tick(cpu);
        match ExceptionCode::from_u32(cpu.exception.code) {
            ExceptionCode::Syscall => self.handle_syscall(cpu),
            ExceptionCode::Environment => todo!(),
            _ => None,
        }
    }

    fn snapshot(&mut self) -> Box<dyn std::any::Any> {
        // @fixme: add support for snapshotting additional kernel state.
        Box::new(self.process.clone())
    }

    fn restore(&mut self, snapshot: &Box<dyn std::any::Any>) {
        self.process = snapshot.downcast_ref::<Process>().unwrap().clone();
    }

    fn next_timer(&self) -> u64 {
        u64::MAX
    }

    fn symbolize_addr(&mut self, cpu: &mut icicle_cpu::Cpu, addr: u64) -> Option<SourceLocation> {
        if let Some(info) = self.process.debug_info.as_ref().and_then(|x| x.symbolize_addr(addr)) {
            return Some(info);
        }

        if let Some(lib) = self.find_containing_library(cpu.mem(), addr) {
            let mut name = vec![];
            self.read_library_name(cpu.mem(), lib, &mut name).ok()?;
            return Some(SourceLocation {
                library_name_and_offset: Some((name, lib.l_addr)),
                ..SourceLocation::default()
            });
        }

        // Failed to find debug info in the main binary, check whether this address is inside of a
        // dynamically linked library that we don't have debug or symbol info for.
        //
        // @fixme: actually load the debug info here.
        for (start, entry) in self.process.mapping.range(..addr).rev() {
            if addr < entry.end {
                return Some(SourceLocation {
                    library_name_and_offset: Some((entry.path.clone(), *start)),
                    ..SourceLocation::default()
                });
            }
        }

        None
    }

    fn lookup_symbol(&mut self, symbol: &str) -> Option<u64> {
        if let Some(addr) =
            self.process.debug_info.as_ref().and_then(|x| x.symbols.resolve_sym(symbol))
        {
            return Some(addr);
        }
        // @todo: check exported library functions?
        None
    }
}

#[derive(Debug, Clone, Copy)]
pub struct LinkMapEntry {
    pub l_addr: u64,
    pub l_name: u64,
    pub l_ld: u64,
    pub l_next: u64,
    pub l_prev: u64,
}

pub struct LinkMapIter<'a, M> {
    arch: &'a arch::KernelArch,
    mem: &'a mut M,
    next: u64,
}

impl<'a, M: LinuxMmu> Iterator for LinkMapIter<'a, M> {
    type Item = (u64, LinkMapEntry);

    fn next(&mut self) -> Option<Self::Item> {
        if self.next == 0 {
            return None;
        }

        let mut link_map = self.arch.libc(self.next);
        let entry = LinkMapEntry {
            l_addr: link_map.read::<arch::Ptr, _>(self.mem).ok()?,
            l_name: link_map.read::<arch::Ptr, _>(self.mem).ok()?,
            l_ld: link_map.read::<arch::Ptr, _>(self.mem).ok()?,
            l_next: link_map.read::<arch::Ptr, _>(self.mem).ok()?,
            l_prev: link_map.read::<arch::Ptr, _>(self.mem).ok()?,
        };
        let addr = self.next;
        self.next = entry.l_next;
        Some((addr, entry))
    }
}
