//! Virtual file system (VFS) implementation for Icicle.
//!
//! This crate is designed to emulate the outward behavior of the Linux VFS implementation. However,
//! it has been greatly simplified and is designed to be "snapshotable"

pub use self::file::{ActiveFile, ActiveFileData, FileTable, OpenFlags};

pub mod devices;
pub mod host;
pub mod socket;

mod file;

use std::{
    any::Any,
    cell::RefCell,
    collections::{hash_map::Entry as HashEntry, HashMap, VecDeque},
    rc::Rc,
};

use bstr::ByteSlice;

use crate::{errno, fs::host::TempFs, sys, types};

pub type Errno = u64;
pub type Result<T> = std::result::Result<T, Errno>;

pub type FileName = Vec<u8>;
pub type FileNameRef<'a> = &'a [u8];

pub type Path = Vec<u8>;
pub type PathRef<'a> = &'a [u8];

/// A globally unique reference to an inode, consiting of a device number and an inode number.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct InodeIndex {
    /// The file-system/device that this inode belongs to.
    pub dev: usize,

    /// A unique identifier for the inode within the file-system.
    pub ino: usize,
}

impl std::fmt::Display for InodeIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(dev={}, ino={})", self.dev, self.ino)
    }
}

#[derive(Clone, Copy)]
pub struct InodeVtable {
    /// Prepare the inode for opening.
    ///
    /// ## Errors
    ///
    /// - `EIO` if an file-system specific I/O error occured.
    pub open: fn(inode: &mut Inode) -> Result<()>,

    /// Create a new file with name `name` in `dir`.
    pub create: fn(inode: &mut Inode, dir: &DirEntryRef, name: FileName) -> Result<DirEntryRef>,

    /// Delete a file with name `name` in `dir`
    pub remove: fn(inode: &mut Inode, dir: &DirEntryRef, name: FileNameRef) -> Result<InodeRef>,

    /// Retrieve metadata about the inode.
    pub stat: fn(inode: &mut Inode) -> Result<types::Stat>,

    /// Read bytes at `offset` into `buf` returning the numbers of bytes read.
    ///
    /// ## Errors
    ///
    /// - `EIO` if an file-system specific I/O error occured.
    /// - `EISDIR` if this inode is a directory.
    /// - `ESPIPE` if the inode corresponds to `pipe`-like object and `offset` is not at the end of
    ///   the file.
    pub read: fn(inode: &mut Inode, offset: usize, buf: &mut [u8]) -> Result<usize>,

    /// Write bytes from `buf` to `offset`
    ///
    /// ## Errors
    ///
    /// - `EIO` if an file-system specific I/O error occured.
    /// - `EISDIR` if this inode is a directory.
    /// - `ESPIPE` if the inode corresponds to `pipe`-like object and `offset` is not at the end of
    ///   the file.
    pub write: fn(inode: &mut Inode, offset: usize, buf: &[u8]) -> Result<usize>,

    /// Poll the file descriptor, checking whether any of the requested `events` are ready.
    pub poll: fn(inode: &mut Inode, events: u64) -> u64,

    /// Receive send a message to a socket.
    pub sendto: fn(inode: &mut Inode, msg: &socket::Message) -> Result<usize>,

    /// Receive a message from a socket.
    pub recvfrom: fn(inode: &mut Inode, msg: &mut socket::Message) -> Result<usize>,

    /// Bind a socket to an address.
    pub bind: fn(inode: &mut Inode, addr: &socket::SocketAddr) -> Result<()>,

    /// Get reference to the raw underlying bytes of `inode`.
    ///
    /// @fixme: this is currently used for mmaping a file, however this api does not allow
    /// modifications to the memory map to actually modify the underlying file.
    pub slice: fn(inode: &mut Inode, offset: usize, len: usize) -> Result<&[u8]>,

    /// Get the `DirEntry` associated the nth child of `inode`.
    ///
    /// ## Errors
    ///
    ///  - `ENOTDIR` is returned  when `parent` is not a directory.
    ///  - `ENOENT` is returned when `n` is larger than the number of children in the directory.
    pub iterate_dir: fn(inode: &mut Inode, n: usize) -> Result<(Path, InodeRef)>,

    /// Create a new directory named `name` under `dir`.
    pub create_dir: fn(inode: &mut Inode, dir: &DirEntryRef, name: FileName) -> Result<DirEntryRef>,

    /// Create a new regular file named `name` under `dir`.
    pub create_file:
        fn(inode: &mut Inode, dir: &DirEntryRef, name: FileName) -> Result<DirEntryRef>,

    /// Attempt to resolve `name` within the directory referenced by `parent`, returning a
    /// reference to the entry corresponding to `name` on success.
    ///
    /// ## Errors
    ///
    ///  - `ENOTDIR` is returned  when `parent` is not a directory
    ///  - `ENOENT` is returned when the `parent` is a directory but `name` does not exist in the
    ///    directory.
    pub lookup: fn(inode: &mut Inode, dir: &DirEntryRef, name: FileNameRef) -> Result<DirEntryRef>,
}

pub static DEFAULT_INODE_VTABLE: InodeVtable = InodeVtable {
    open: |_| Ok(()),
    create: |_, _, _| Err(errno::ENOTDIR),
    remove: |_, _, _| Err(errno::ENOTDIR),
    stat: Inode::stat,
    read: |_, _, _| Err(errno::EISDIR),
    write: |_, _, _| Err(errno::EISDIR),
    poll: |_, _| 0,
    recvfrom: |_, _| Err(errno::ENOTSOCK),
    sendto: |_, _| Err(errno::ENOTSOCK),
    bind: |_, _| Err(errno::ENOTSOCK),
    slice: |_, _, _| Err(errno::EPERM),
    iterate_dir: |_, _| Err(errno::ENOTDIR),
    create_dir: |_, _, _| Err(errno::ENOTDIR),
    create_file: |_, _, _| Err(errno::ENOTDIR),
    lookup: |_, _, _| Err(errno::ENOTDIR),
};

/// Represents a view of a file from the perspective of a particular file-system.
pub struct Inode {
    /// Globally unique index to this inode.
    pub index: InodeIndex,

    /// A reference to the file-system that this inode belongs to.
    pub file_system: Option<std::rc::Weak<RefCell<dyn FileSystem>>>,

    /// File specific data associated with the inode.
    pub data: Box<dyn Any>,

    /// The operations to manipulate this inode
    pub vtable: &'static InodeVtable,

    /// The type of the inode
    pub kind: FileKind,

    /// The user ID of the file owner
    pub uid: u64,

    /// The group ID of the file owner
    pub gid: u64,

    /// Access bits for this inode
    pub access: u16,

    /// File size of the inode
    pub size: u64,

    /// The time the resource was last modified (nanoseconds)
    pub modified: i128,

    /// The time the resource was last modified (nanoseconds)
    pub created: i128,

    /// The file creation time (nanoseconds)
    pub accessed: i128,

    /// The block size to use for system io
    pub block_size: u64,

    /// The physical memory address where this inode is mapped to
    // @fixme: this is not properly supported
    pub mapped_addr: Option<u64>,

    /// Configures whether to generate a VmExit will be generated whenever this inode is first
    /// interacted with
    pub hooked: bool,
}

impl Drop for Inode {
    fn drop(&mut self) {
        // Notify the file system of deletion of this inode
        if let Some(fs) = self.file_system.as_ref().and_then(|fs| fs.upgrade()) {
            fs.borrow_mut().remove_inode(self.index.ino);
        }
    }
}

impl Inode {
    pub fn new(index: InodeIndex) -> Self {
        let mut new = Self::default();
        new.index = index;
        new
    }

    pub fn is_dir(&self) -> bool {
        self.kind == FileKind::Directory
    }

    fn stat(&mut self) -> Result<types::Stat> {
        if self.hooked {
            return Err(errno::HOOKED);
        }

        let mode = self.access as u32 | self.kind.mode_bits();

        let (atime, atime_nsec) = split_seconds_and_nanos(self.accessed);
        let (ctime, ctime_nsec) = split_seconds_and_nanos(self.created);
        let (mtime, mtime_nsec) = split_seconds_and_nanos(self.modified);

        let stat = types::Stat {
            dev: self.index.dev as u64,
            ino: self.index.ino as u64,
            mode,
            size: self.size as i64,
            blksize: self.block_size as i64,
            atime,
            atime_nsec,
            ctime,
            ctime_nsec,
            mtime,
            mtime_nsec,
            ..types::Stat::debug_stat()
        };
        tracing::trace!("{:?}", stat);

        Ok(stat)
    }
}

fn split_seconds_and_nanos(time: i128) -> (i64, i64) {
    const NANOS_TO_SECONDS: i128 = 1_000_000_000;
    let (seconds, nanos) = (time / NANOS_TO_SECONDS, time % NANOS_TO_SECONDS);
    (seconds as i64, nanos as i64)
}

impl Default for Inode {
    fn default() -> Self {
        Self {
            index: InodeIndex { dev: 0, ino: 0 },
            file_system: None,
            data: Box::new(()),
            vtable: &DEFAULT_INODE_VTABLE,
            kind: FileKind::Invalid,
            uid: 0,
            gid: 0,
            access: 0,
            size: 0,
            modified: 0,
            created: 0,
            accessed: 0,
            mapped_addr: None,
            hooked: false,
            block_size: 512,
        }
    }
}

pub type InodeRef = Rc<RefCell<Inode>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Directory,
    CharacterDevice,
    BlockDevice,
    RegularFile,
    Fifo,
    SymbolicLink,
    Socket,
    Invalid,
}

impl FileKind {
    #[rustfmt::skip]
    pub fn mode_bits(&self) -> u32 {
        match self {
            Self::SymbolicLink      => 0o010000,
            Self::CharacterDevice   => 0o020000,
            Self::Directory         => 0o040000,
            Self::BlockDevice       => 0o060000,
            Self::RegularFile       => 0o100000,
            Self::Fifo              => 0o120000,
            Self::Socket            => 0o140000,
            Self::Invalid           => panic!(),
        }
    }
}

impl Default for FileKind {
    fn default() -> Self {
        Self::Invalid
    }
}

/// Represents the view of a file from the perspective of the VFS
pub struct DirEntry {
    /// The file-name associated with this file.
    pub name: FileName,

    /// A reference to the underlying inode.
    pub inode: std::rc::Weak<RefCell<Inode>>,

    /// The parent of this file or `None` this entry corresponds to the root.
    pub parent: Option<DirEntryRef>,

    /// The file-system mounted at this location.
    pub mount: Option<DirEntryRef>,
}

impl DirEntry {
    pub fn is_dir(&self) -> bool {
        self.inode.upgrade().map_or(false, |x| x.borrow().is_dir())
    }
}

pub type DirEntryRef = Rc<RefCell<DirEntry>>;

/// Operations that can be performed on a file-system
pub trait FileSystem {
    /// Gets the name of this file system.
    fn name(&self) -> &str;

    /// Gets the device id associated with the file system.
    fn id(&self) -> usize;

    /// Allocate a new inode within the file system.
    fn alloc_inode(&mut self) -> Result<InodeRef>;

    /// Stop tracking an `ino` in the file system.
    fn remove_inode(&mut self, ino: usize);

    /// Look-up an inode with the file-system
    fn inode(&self, ino: usize) -> std::rc::Weak<RefCell<Inode>>;
}

pub struct FileSystemCore {
    /// The device number assigned to this file system.
    pub dev_id: usize,

    /// The inode number that will be assigned to the next file loaded.
    pub next_inode: usize,

    /// Keeps track of all inodes managed by this file system.
    pub inodes: HashMap<usize, std::rc::Weak<RefCell<Inode>>>,
}

const DEFAULT_STREAM_CAPACITY: usize = 4096;

#[derive(Clone)]
pub struct Stream {
    // @todo: switch to fixed size ring buffer
    data: VecDeque<u8>,

    // note: need this field separate because `VecDeque` doesn't ensure that the capacity will not
    // be exceeded.
    capacity: usize,
}

impl Default for Stream {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_STREAM_CAPACITY)
    }
}

impl Stream {
    pub fn with_capacity(capacity: usize) -> Self {
        Self { data: VecDeque::with_capacity(capacity), capacity }
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.data.is_empty() {
            return Err(errno::EWOULDBLOCK);
        }

        let len = usize::min(self.data.len(), buf.len());
        for (dst, src) in buf.iter_mut().zip(&mut self.data.drain(..len)) {
            *dst = src;
        }
        Ok(len)
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let len = usize::min(buf.len(), self.capacity - self.data.len());
        if len == 0 {
            return Err(errno::EWOULDBLOCK);
        }
        self.data.extend(&buf[..len]);
        Ok(len)
    }

    pub fn is_full(&self) -> bool {
        self.capacity <= self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// Maximum number of bytes a pipe can store without blocking.
const PIPE_CAPACITY: usize = 4096;

pub struct Pipe {
    /// The number of bytes read from the pipe
    pub read_offset: usize,

    /// The number of bytes written to the pipe
    pub write_offset: usize,

    /// The unread content of the pipe
    pub data: Stream,
}

impl Pipe {
    pub fn new() -> Self {
        Self { data: Stream::with_capacity(PIPE_CAPACITY), read_offset: 0, write_offset: 0 }
    }

    pub fn read(inode: &mut Inode, offset: usize, buf: &mut [u8]) -> Result<usize> {
        let pipe = inode.data.downcast_mut::<Self>().unwrap();

        if offset != pipe.read_offset {
            return Err(errno::ESPIPE);
        }

        let len = pipe.data.read(buf)?;
        pipe.read_offset += len;
        Ok(len)
    }

    pub fn write(inode: &mut Inode, offset: usize, buf: &[u8]) -> Result<usize> {
        let pipe = inode.data.downcast_mut::<Self>().unwrap();

        if offset != pipe.write_offset {
            return Err(errno::ESPIPE);
        }

        pipe.write_offset += pipe.data.write(buf)?;
        Ok(buf.len())
    }

    pub fn poll(inode: &mut Inode, events: u64) -> u64 {
        let pipe = inode.data.downcast_ref::<Self>().unwrap();

        let mut revents = 0;

        if events & sys::poll::POLLIN != 0 && !pipe.data.is_empty() {
            revents |= sys::poll::POLLIN;
        }

        if events & sys::poll::POLLOUT != 0 && !pipe.data.is_full() {
            revents |= sys::poll::POLLOUT;
        }

        revents
    }
}

static PIPE_VTABLE: InodeVtable =
    InodeVtable { read: Pipe::read, write: Pipe::write, poll: Pipe::poll, ..DEFAULT_INODE_VTABLE };

pub struct PipeFs {
    fs: Rc<RefCell<TempFs>>,
}

impl PipeFs {
    pub fn create(dev_id: usize) -> Self {
        Self { fs: TempFs::create(dev_id) }
    }

    pub fn create_pipe(&mut self) -> Result<InodeRef> {
        let inode = self.fs.borrow_mut().alloc_inode()?;
        {
            let mut inode = inode.borrow_mut();
            inode.data = Box::new(Pipe::new());
            inode.vtable = &PIPE_VTABLE;
            inode.kind = FileKind::Fifo;
        }

        Ok(inode)
    }

    pub fn alloc_file(&mut self, inode: InodeRef) -> Result<ActiveFile> {
        Ok(Rc::new(RefCell::new(ActiveFileData::new(vec![], inode))))
    }
}

/// The root structure for the virtual file-system.
pub struct VfsRoot {
    pub root: DirEntryRef,

    pub pipefs: PipeFs,
    pub sockfs: socket::SocketFs,

    /// Keeps track of the children of each `DirEntry` that we have seen so far.
    dir_cache: HashMap<(InodeIndex, FileName), DirEntryRef>,

    file_systems: HashMap<usize, Rc<RefCell<dyn FileSystem>>>,
}

impl VfsRoot {
    pub fn new() -> Self {
        let tmp_fs = host::TempFs::create(0);
        let root = DirEntry {
            name: b"/".to_vec(),
            inode: tmp_fs.borrow().inode(0),
            parent: None,
            mount: None,
        };

        let mut file_systems = HashMap::new();
        file_systems.insert(0, tmp_fs as Rc<RefCell<dyn FileSystem>>);

        Self {
            root: Rc::new(RefCell::new(root)),
            pipefs: PipeFs::create(0x8000),
            sockfs: socket::SocketFs::create(0x8001),
            dir_cache: HashMap::new(),
            file_systems,
        }
    }

    /// Initialize the VFS to the most commonly used default state
    pub fn init_default(&mut self, host_root: std::path::PathBuf) -> Result<()> {
        let root = self.root.clone();

        // Map host_root to VFS root
        if let Err(e) = host::map_host(&host_root, &root.borrow().inode.upgrade().unwrap()) {
            tracing::error!("Host mapping of: {} failed: {}", host_root.display(), e);
            return Err(errno::EIO);
        }

        // Initialize system file systems
        // @todo: these shouldn't just be mapped to tmpfs
        self.mount(b"/dev", host::TempFs::create(1))?;
        self.mount(b"/proc", host::TempFs::create(2))?;
        self.mount(b"/sys", host::TempFs::create(3))?;
        self.mount(b"/run", host::TempFs::create(4))?;

        // Add some standard devices
        self.create_dev(b"/dev/null", devices::NullDevice)?;
        self.create_dev(b"/dev/zero", devices::ZeroDevice)?;
        self.create_dev(b"/dev/urandom", devices::RandomDevice::new(0x1234))?;

        // @fixme: these should be symlinks instead of devices
        self.create_dev(b"/dev/stdin", devices::NullDevice)?;
        self.create_dev(b"/dev/stdout", devices::NullDevice)?;
        self.create_dev(b"/dev/stderr", devices::NullDevice)?;

        Ok(())
    }

    /// Read the entire contents a path from the file system creating a file descriptor
    pub fn read_raw(&mut self, path: PathRef) -> Result<Vec<u8>> {
        let dentry = self.resolve(self.root.clone(), path)?;
        let dentry_ref = dentry.borrow();

        with_inode_mut(&dentry_ref.inode, |inode| {
            let mut buf = vec![0; inode.size as usize];
            (inode.vtable.open)(inode)?;
            let count = (inode.vtable.read)(inode, 0, &mut buf)?;
            if count != buf.len() {
                tracing::error!("Error reading file: {} out of {} bytes read", count, buf.len());
                return Err(errno::EIO);
            }
            Ok(buf)
        })
    }

    // Copy the full path from the root to `dir` into `buf`
    pub fn path_to_root(&self, dentry: &DirEntry, buf: &mut Path) {
        if let Some(parent) = &dentry.parent {
            if !Rc::ptr_eq(parent, &self.root) {
                self.path_to_root(&parent.borrow(), buf);
            }
            buf.push(b'/');
        }
        buf.extend_from_slice(&dentry.name);
    }

    /// Resolve `path` to a `DirEntry` starting from `dir`.
    pub fn resolve(&mut self, dir: DirEntryRef, path: PathRef) -> Result<DirEntryRef> {
        if path.is_empty() {
            return Ok(dir);
        }

        match self.walk_path(dir, path, VfsRoot::resolve_one) {
            Ok(ent) => {
                tracing::trace!("resolve: {} -> {}", path.as_bstr(), ent.borrow().name.as_bstr());
                Ok(ent)
            }
            Err(e) => {
                tracing::trace!("resolve: {} -> -{}", path.as_bstr(), e);
                Err(e)
            }
        }
    }

    fn resolve_one(&mut self, dir: &DirEntryRef, name: PathRef) -> Result<DirEntryRef> {
        let inode = &dir.borrow().inode;
        let index = inode.upgrade().ok_or(errno::ENOENT)?.borrow().index;

        match self.dir_cache.entry((index, name.to_owned())) {
            HashEntry::Occupied(entry) => Ok(entry.get().clone()),
            HashEntry::Vacant(slot) => {
                let child = with_inode_mut(inode, |inode| (inode.vtable.lookup)(inode, dir, name))?;
                Ok(slot.insert(child).clone())
            }
        }
    }

    pub fn walk_path<'a>(
        &mut self,
        mut dir: DirEntryRef,
        mut path: PathRef<'a>,
        mut walk_entry: impl FnMut(&mut Self, &DirEntryRef, PathRef<'a>) -> Result<DirEntryRef>,
    ) -> Result<DirEntryRef> {
        // If the path starts with `/` then this is an absolute path instead of a relataive path.
        if path.starts_with(b"/") {
            dir = self.root.clone();
        }
        path = path.trim_start_with(|c| c == '/');

        // Resolve each component in `path`
        while !path.is_empty() {
            let pos = path.find_char('/').unwrap_or(path.len());
            let (name, remaining) = path.split_at(pos);
            path = remaining.trim_start_with(|c| c == '/');

            match name {
                // A special path representing the current directory
                b"." => {}

                // A special path representing the parent directory
                b".." => {
                    let parent = dir.borrow().parent.clone();
                    if let Some(parent) = parent {
                        dir = parent;
                    }
                }

                _ => dir = walk_entry(self, &dir, name)?,
            }

            // Follow mount if there is a file-system mounted at this location
            let mount = dir.borrow().mount.clone();
            if let Some(inner) = mount {
                tracing::trace!("found mount point at: {}", name.as_bstr());
                dir = inner;
            }
        }

        Ok(dir)
    }

    pub fn resolve_parent<'a>(
        &mut self,
        dir: &DirEntryRef,
        path: PathRef<'a>,
    ) -> Result<(DirEntryRef, PathRef<'a>)> {
        let (name, parent) = match split_filename(path) {
            Some(entry) => entry,
            None => return Ok((dir.clone(), path)),
        };

        if parent.is_empty() {
            return Ok((self.root.clone(), name));
        }

        Ok((self.resolve(dir.clone(), parent)?, name))
    }

    /// Open the file at `path` starting from the root directory.
    pub fn open(&mut self, path: PathRef, flags: OpenFlags) -> Result<ActiveFile> {
        self.open_at(&self.root.clone(), path, flags)
    }

    /// Open the file at `path` starting from the directory `dir`.
    pub fn open_at(
        &mut self,
        dir: &DirEntryRef,
        path: PathRef,
        flags: OpenFlags,
    ) -> Result<ActiveFile> {
        tracing::trace!("open_at: dir={} path={}", dir.borrow().name.as_bstr(), path.as_bstr());
        if path.is_empty() {
            return Err(errno::ENOENT);
        }
        let (parent, name) = self.resolve_parent(dir, path)?;
        self.open_or_create_file(parent, name, flags)
    }

    fn open_or_create_file(
        &mut self,
        parent: DirEntryRef,
        name: PathRef,
        flags: OpenFlags,
    ) -> Result<ActiveFile> {
        let dentry = match self.resolve(parent.clone(), name) {
            Ok(dentry) => dentry,
            Err(errno::ENOENT) if flags.contains(OpenFlags::O_CREAT) => {
                let inode = parent.borrow().inode.upgrade().ok_or(errno::ENOENT)?;
                let mut inode = inode.borrow_mut();
                (inode.vtable.create_file)(&mut inode, &parent, name.to_vec())?
            }
            Err(e) => return Err(e),
        };

        let inode = dentry.borrow().inode.upgrade().ok_or(errno::ENOENT)?;
        {
            let mut inode = inode.borrow_mut();
            // @fixme: handle extra behavior for other open modes
            (inode.vtable.open)(&mut inode)?;
        }

        let mut path = vec![];
        self.path_to_root(&dentry.borrow(), &mut path);

        Ok(Rc::new(RefCell::new(ActiveFileData::new(path, inode))))
    }

    pub fn mount(&mut self, path: PathRef, fs: Rc<RefCell<dyn FileSystem>>) -> Result<()> {
        tracing::trace!("mounting {} at {}", fs.borrow().name(), path.as_bstr());
        let dentry = match self.resolve(self.root.clone(), path) {
            Ok(dentry) => dentry,
            Err(errno::ENOENT) => {
                let root = self.root.clone();
                self.create_dir(&root, path, 0)?
            }
            Err(e) => return Err(e),
        };
        self.mount_at(&dentry, fs)
    }

    pub fn mount_at(
        &mut self,
        dentry: &DirEntryRef,
        fs: Rc<RefCell<dyn FileSystem>>,
    ) -> Result<()> {
        let inode = fs.borrow().inode(0);
        let mut dir = dentry.borrow_mut();
        dir.mount = Some(Rc::new(RefCell::new(DirEntry {
            name: dir.name.clone(),
            inode,
            parent: dir.parent.clone(),
            mount: None,
        })));

        let id = fs.borrow().id();
        self.file_systems.insert(id, fs);

        Ok(())
    }

    /// Create a directory named `name` in `dir` with `mode`
    pub fn create_dir(
        &mut self,
        dir: &DirEntryRef,
        path: PathRef,
        _mode: u64,
    ) -> Result<DirEntryRef> {
        tracing::trace!("create_dir: {}", path.as_bstr());
        let (parent, name) = self.resolve_parent(dir, path)?;

        let inode = parent.borrow().inode.upgrade().ok_or(errno::ENOENT)?;
        let mut inode = inode.borrow_mut();
        (inode.vtable.create_dir)(&mut inode, &parent, name.to_vec())
    }

    /// Create a file named `name` in `dir` with `mode`
    pub fn create_file(
        &mut self,
        dir: &DirEntryRef,
        path: PathRef,
        _mode: u64,
    ) -> Result<DirEntryRef> {
        tracing::trace!("create_file: {}", path.as_bstr());
        let (parent, name) = self.resolve_parent(dir, path)?;

        let inode = parent.borrow().inode.upgrade().ok_or(errno::ENOENT)?;
        let mut inode = inode.borrow_mut();
        (inode.vtable.create_file)(&mut inode, &parent, name.to_vec())
    }

    pub fn create_dir_all(
        &mut self,
        dir: &DirEntryRef,
        path: PathRef,
        _mode: u64,
    ) -> Result<DirEntryRef> {
        self.walk_path(dir.clone(), path, |vfs, dir, name| match vfs.resolve_one(dir, name) {
            Ok(next) => Ok(next),
            Err(errno::ENOENT) => {
                let inode = dir.borrow().inode.upgrade().ok_or(errno::ENOENT)?;
                let mut inode = inode.borrow_mut();
                (inode.vtable.create_dir)(&mut inode, dir, name.to_vec())
            }
            Err(e) => Err(e),
        })
    }

    /// Gets or creates the file at `path`, recursively creating all parent directories if required.
    pub fn get_or_create_recursive(&mut self, path: PathRef) -> Result<DirEntryRef> {
        let root = self.root.clone();
        if let Some((_, parent)) = split_filename(path) {
            self.create_dir_all(&root, parent, 0)?;
        }
        let (parent, name) = self.resolve_parent(&root, path)?;

        let inode_ref = parent.borrow().inode.upgrade().ok_or(errno::ENOENT)?;

        let mut inode = inode_ref.borrow_mut();
        match (inode.vtable.lookup)(&mut inode, &parent, name) {
            Ok(entry) => Ok(entry),
            Err(errno::ENOENT) => (inode.vtable.create)(&mut inode, &parent, name.to_vec()),
            Err(e) => Err(e),
        }
    }

    /// Create/replace a device named `name` at `path`.
    pub fn create_dev<T>(&mut self, path: PathRef, device: T) -> Result<DirEntryRef>
    where
        T: devices::Device + 'static,
    {
        tracing::trace!("create_dev: {}", path.as_bstr());

        let dentry = self.get_or_create_recursive(path)?;
        with_inode_mut(&dentry.borrow().inode, |inode| {
            inode.hooked = false;
            devices::map_device(inode, Box::new(device));
            Ok(())
        })?;

        Ok(dentry)
    }

    /// Unlink file at `path` starting from the directory `dir`.
    pub fn unlink_at(&mut self, dir: &DirEntryRef, path: PathRef) -> Result<()> {
        if path.is_empty() {
            return Err(errno::ENOENT);
        }
        let (parent, name) = self.resolve_parent(dir, path)?;

        let inode = parent.borrow().inode.upgrade().ok_or(errno::ENOENT)?;
        let mut inode = inode.borrow_mut();
        (inode.vtable.remove)(&mut inode, &parent, name)?;

        Ok(())
    }

    /// Configure the file at `path` to generate a [icicle_cpu::VmExit] on first use.
    pub fn hook_path(&mut self, path: PathRef) -> Result<DirEntryRef> {
        let dentry = self.get_or_create_recursive(path)?;
        with_inode_mut(&dentry.borrow().inode, |inode| {
            inode.hooked = true;
            Ok(())
        })?;
        Ok(dentry)
    }
}

pub fn with_inode_mut<T>(
    inode: &std::rc::Weak<RefCell<Inode>>,
    func: impl FnOnce(&mut Inode) -> Result<T>,
) -> Result<T> {
    let inode = inode.upgrade().ok_or(errno::ENOENT)?;
    let mut inode_ref = inode.borrow_mut();
    func(&mut inode_ref)
}

/// Split a path into two components: (filename, parent path)
fn split_filename(path: PathRef) -> Option<(PathRef, PathRef)> {
    let mut iter = path.rsplitn(2, |&x| x == b'/');
    Some((iter.next()?, iter.next()?))
}
