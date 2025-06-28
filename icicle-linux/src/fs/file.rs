use std::{cell::RefCell, collections::BTreeSet, rc::Rc};

use bstr::ByteSlice;
use icicle_cpu::mem::perm;

use crate::{errno, fs::socket, types, LinuxMmu, ProcessManager};

use super::{InodeRef, Path, Result};

pub type FileDescriptor = u64;
pub type ActiveFile = Rc<RefCell<ActiveFileData>>;

#[derive(Default)]
pub struct FileTable {
    /// The list of open files, index by file descriptor.
    pub files: Vec<Option<ActiveFile>>,

    /// List of free file descriptors.
    pub free_files: BTreeSet<FileDescriptor>,
}

/// Active files are reference counted, but when we clone the file table (e.g. for a snapshot) we
/// want a deep copy so we need a manual clone implementation.
impl Clone for FileTable {
    fn clone(&self) -> Self {
        Self {
            files: self
                .files
                .iter()
                .map(|slot| slot.as_ref().map(|value| Rc::new((**value).clone())))
                .collect(),
            free_files: self.free_files.clone(),
        }
    }
}

impl FileTable {
    pub fn new() -> Self {
        Self { files: vec![], free_files: BTreeSet::new() }
    }

    /// Get a reference to the file associated with `fd`, returning `EBADF` if `fd` does not
    /// reference an open file.
    ///
    /// This will also send events to any process listening for changes to this file.
    pub fn get(&mut self, pm: &mut ProcessManager, fd: FileDescriptor) -> Result<ActiveFile> {
        let file = self.files.get(fd as usize).and_then(|x| x.clone()).ok_or(errno::EBADF)?;
        for pid in &file.borrow_mut().listeners {
            pm.file_ready_event(*pid, fd);
        }
        Ok(file)
    }

    /// Set `fd` to map to `file`, implicitly unmapping any existing file.
    ///
    /// Note: This will also send events to any process listening for changes to this file.
    pub fn set(&mut self, pm: &mut ProcessManager, fd: FileDescriptor, file: ActiveFile) {
        let index = fd as usize;
        if index >= self.files.len() {
            self.free_files.extend(self.files.len() as u64..fd);
            self.files.resize(index + 1, None);
        }

        if let Some(existing) = std::mem::replace(&mut self.files[fd as usize], Some(file)) {
            let existing = existing.borrow();
            let name = existing.path.as_bstr();

            for pid in &existing.listeners {
                pm.file_ready_event(*pid, fd);
            }
            tracing::debug!("{} closed because fd={} was reassigned", name, fd);
        }

        self.free_files.remove(&fd);
    }

    /// Remove the file associated with `fd` from the mapping table.
    ///
    /// Note: This will also send events to any process listening for changes to this file.
    pub fn close(&mut self, pm: &mut ProcessManager, fd: FileDescriptor) -> Result<()> {
        if let Some(existing) = self.files.get_mut(fd as usize).and_then(|x| x.take()) {
            let existing = existing.borrow();
            let name = existing.path.as_bstr();
            tracing::debug!("closed {} (fd={})", name, fd);
            self.free_files.insert(fd);

            for pid in &existing.listeners {
                pm.file_ready_event(*pid, fd);
            }

            Ok(())
        }
        else {
            Err(errno::EBADF)
        }
    }

    /// Allocate a new file descriptor associated with `file`
    pub fn add(&mut self, file: ActiveFile) -> FileDescriptor {
        match self.free_files.pop_first() {
            Some(fd) => {
                self.files[fd as usize] = Some(file);
                fd
            }
            None => {
                self.files.push(Some(file));
                (self.files.len() - 1) as u64
            }
        }
    }
}

/// Represents the data attached to a file descriptor.
///
/// (Corresponds to `struct file` from the Linux kernel)
#[derive(Clone)]
pub struct ActiveFileData {
    /// The full path used to open the file.
    pub path: Path,

    /// The inode associated with the open file.
    pub inode: InodeRef,

    /// The offset or position we are inside of the file
    pub pos: usize,

    /// Flags associated with the file
    pub flags: u64,

    /// PIDs of processes that are waiting for file events.
    pub listeners: BTreeSet<u64>,
}

impl ActiveFileData {
    pub fn new(path: Path, inode: InodeRef) -> Self {
        Self { path, inode, pos: 0, flags: 0, listeners: BTreeSet::new() }
    }
}
// @fixme: cleanup handling of file hooks.
// @fixme: improve function dispatch.
impl ActiveFileData {
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut inode = self.inode.borrow_mut();
        if inode.hooked {
            return Err(errno::HOOKED);
        }

        let count = (inode.vtable.read)(&mut inode, self.pos, buf)?;
        self.pos += count;
        Ok(count)
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let mut inode = self.inode.borrow_mut();
        if inode.hooked {
            return Err(errno::HOOKED);
        }

        let count = (inode.vtable.write)(&mut inode, self.pos, buf)?;
        self.pos += count;
        Ok(count)
    }

    pub fn seek(&mut self, offset: i64, whence: types::Seek) -> Result<usize> {
        if self.inode.borrow().hooked {
            return Err(errno::HOOKED);
        }

        let new = match whence {
            types::Seek::Set => Some(offset),
            types::Seek::Cur => (self.pos as i64).checked_add(offset),
            types::Seek::End => (self.inode.borrow().size as i64).checked_add(offset),
            types::Seek::Data | types::Seek::Hole => return Err(errno::EINVAL),
        };

        self.pos = match new {
            Some(x) if x < 0 => return Err(errno::EINVAL),
            Some(x) => x as usize,
            None => return Err(errno::EOVERFLOW),
        };

        Ok(self.pos)
    }

    pub fn poll(&mut self, events: u64) -> Result<u64> {
        let mut inode = self.inode.borrow_mut();
        if inode.hooked {
            return Err(errno::HOOKED);
        }

        Ok((inode.vtable.poll)(&mut inode, events))
    }

    pub fn iterate_dir(&mut self) -> Result<(Path, InodeRef)> {
        let mut inode = self.inode.borrow_mut();
        if inode.hooked {
            return Err(errno::HOOKED);
        }

        let entry = (inode.vtable.iterate_dir)(&mut inode, self.pos)?;
        self.pos += 1;
        Ok(entry)
    }

    pub fn mmap<M>(&mut self, mem: &mut M, offset: u64, virt_addr: u64, len: u64) -> Result<usize>
    where
        M: LinuxMmu,
    {
        let mut inode = self.inode.borrow_mut();
        if inode.hooked {
            return Err(errno::HOOKED);
        }

        let buf = (inode.vtable.slice)(&mut inode, offset as usize, len as usize)?;
        mem.write_bytes_raw(virt_addr, buf, perm::NONE).map_err(|_| errno::EFAULT)?;
        Ok(buf.len())
    }

    pub fn recvfrom(&mut self, msg: &mut socket::Message) -> Result<usize> {
        let mut inode = self.inode.borrow_mut();
        if inode.hooked {
            return Err(errno::HOOKED);
        }
        (inode.vtable.recvfrom)(&mut inode, msg)
    }

    pub fn sendto(&mut self, msg: &socket::Message) -> Result<usize> {
        let mut inode = self.inode.borrow_mut();
        if inode.hooked {
            return Err(errno::HOOKED);
        }
        (inode.vtable.sendto)(&mut inode, msg)
    }

    pub fn bind(&mut self, addr: &socket::SocketAddr) -> Result<()> {
        let mut inode = self.inode.borrow_mut();
        if inode.hooked {
            return Err(errno::HOOKED);
        }
        (inode.vtable.bind)(&mut inode, addr)
    }
}

bitflags::bitflags! {
    #[allow(bad_style)]
    pub struct OpenFlags: u64 {
        const O_ACCMODE     = 0o00000003;
        const O_RDONLY      = 0o00000000;
        const O_WRONLY      = 0o00000001;
        const O_RDWR        = 0o00000002;
        const O_CREAT       = 0o00000100;
        const O_EXCL        = 0o00000200;
        const O_NOCTTY      = 0o00000400;
        const O_TRUNC       = 0o00001000;
        const O_APPEND      = 0o00002000;
        const O_NONBLOCK    = 0o00004000;
        const O_DSYNC       = 0o00010000;
        const FASYNC        = 0o00020000;
        const O_DIRECT      = 0o00040000;
        const O_LARGEFILE   = 0o00100000;
        const O_DIRECTORY   = 0o00200000;
        const O_NOFOLLOW    = 0o00400000;
        const O_NOATIME     = 0o01000000;
        const O_CLOEXEC     = 0o02000000;
    }
}
