//! File system for exposing files/folders from the host in the guest

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    rc::Rc,
};

use bstr::ByteSlice;

use crate::{errno, fs::Path};

use super::{
    DirEntry, DirEntryRef, FileKind, FileName, FileNameRef, FileSystem, Inode, InodeIndex,
    InodeRef, InodeVtable, Result, DEFAULT_INODE_VTABLE,
};

/// Represents a with an allocated inode, but has yet to be actually loaded from the host.
pub struct LazyHostFile {
    /// The location of the file on the host
    pub host_path: PathBuf,
}

impl LazyHostFile {
    fn load(path: PathBuf) -> Self {
        Self { host_path: path }
    }

    fn open(inode: &mut Inode) -> Result<()> {
        let path = {
            let data = inode.data.downcast_mut::<LazyHostFile>().unwrap();
            std::mem::replace(&mut data.host_path, PathBuf::new())
        };
        inode.data = Box::new(VirtualFile::load(path).map_err(|_| errno::EIO)?);
        inode.vtable = &VIRTUAL_FILE_VTABLE;
        Ok(())
    }
}

static LAZY_FILE_VTABLE: InodeVtable =
    InodeVtable { open: LazyHostFile::open, ..DEFAULT_INODE_VTABLE };

pub struct VirtualFile {
    /// The location of the file on the host, or `None` if this file was created by the emulator.
    pub host_path: Option<PathBuf>,

    /// The contents of the file, copy-on-write to allow efficient snapshotting.
    pub contents: Rc<Vec<u8>>,
}

impl VirtualFile {
    pub fn new() -> Self {
        Self { host_path: None, contents: Rc::new(vec![]) }
    }

    pub fn load(path: PathBuf) -> std::io::Result<Self> {
        let data = std::fs::read(&path)?;
        tracing::trace!("read {} ({} bytes)", path.display(), data.len());
        Ok(Self { host_path: Some(path), contents: Rc::new(data) })
    }

    pub fn read(inode: &mut Inode, offset: usize, buf: &mut [u8]) -> Result<usize> {
        let data = inode.data.downcast_ref::<Self>().unwrap();

        if offset >= data.contents.len() {
            return Ok(0);
        }

        let len = usize::min(data.contents.len() - offset, buf.len());
        buf[..len].copy_from_slice(&data.contents[offset..offset + len]);
        Ok(len)
    }

    pub fn write(inode: &mut Inode, offset: usize, buf: &[u8]) -> Result<usize> {
        let data = inode.data.downcast_mut::<Self>().unwrap();

        let new_len = usize::max(data.contents.len(), offset + buf.len());

        let contents = Rc::make_mut(&mut data.contents);
        contents.resize(new_len, 0);
        contents[offset..offset + buf.len()].copy_from_slice(buf);

        Ok(buf.len())
    }

    pub fn slice(inode: &mut Inode, offset: usize, len: usize) -> Result<&[u8]> {
        let data = inode.data.downcast_ref::<Self>().unwrap();

        let mapped_bytes = len.min(data.contents.len().saturating_sub(offset));
        Ok(&data.contents[offset..(offset + mapped_bytes)])
    }
}

static VIRTUAL_FILE_VTABLE: InodeVtable = InodeVtable {
    read: VirtualFile::read,
    write: VirtualFile::write,
    slice: VirtualFile::slice,
    ..DEFAULT_INODE_VTABLE
};

pub struct VirtualDirectory {
    // @fixme: manage unloaded directories separately
    pub host_path: Option<PathBuf>,
    pub children: Option<BTreeMap<FileName, InodeRef>>,
}

impl VirtualDirectory {
    fn load(path: PathBuf) -> std::io::Result<Self> {
        Ok(Self { host_path: Some(path), children: None })
    }

    fn empty() -> Self {
        Self { host_path: None, children: Some(BTreeMap::new()) }
    }

    fn init_children(inode: &mut Inode) -> Result<()> {
        let data: &mut Self = inode.data.downcast_mut::<Self>().unwrap();

        if data.children.is_some() {
            // Children have already been initialized
            return Ok(());
        }

        let mut entries = BTreeMap::new();
        let host_path = data.host_path.as_ref().unwrap();
        for entry in std::fs::read_dir(host_path).map_err(|_| errno::EIO)? {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    tracing::warn!("read_dir error for {}: {}", host_path.display(), e);
                    continue;
                }
            };

            let fs = inode.file_system.as_ref().ok_or(errno::EBADFD)?;
            let child = {
                let fs = fs.upgrade().ok_or(errno::EBADFD)?;
                let mut fs_ref = fs.borrow_mut();
                fs_ref.alloc_inode()?
            };
            let mut child_borrow = child.borrow_mut();
            child_borrow.file_system = Some(fs.clone());
            match resolve_host_path(&entry.path(), &mut child_borrow) {
                Ok(guest_path) => {
                    drop(child_borrow);
                    entries.insert(guest_path, child);
                }
                Err(e) => {
                    tracing::warn!("error resolving {}: {}", entry.path().display(), e)
                }
            }
        }

        data.children = Some(entries);
        Ok(())
    }

    fn lookup(inode: &mut Inode, dir: &DirEntryRef, name: FileNameRef) -> Result<DirEntryRef> {
        Self::init_children(inode)?;
        let data = inode.data.downcast_ref::<Self>().unwrap();
        let child = data.children.as_ref().unwrap().get(name).ok_or(errno::ENOENT)?;

        Ok(Rc::new(RefCell::new(DirEntry {
            name: name.to_vec(),
            inode: Rc::downgrade(child),
            parent: Some(dir.clone()),
            mount: None,
        })))
    }

    fn iterate_dir(inode: &mut Inode, n: usize) -> Result<(Path, InodeRef)> {
        Self::init_children(inode)?;
        let data = inode.data.downcast_ref::<Self>().unwrap();
        data.children
            .as_ref()
            .and_then(|entries| {
                let (name, entry) = entries.iter().nth(n)?;
                Some((name.clone(), entry.clone()))
            })
            .ok_or(errno::ENOENT)
    }

    fn create(inode: &mut Inode, dir: &DirEntryRef, name: FileName) -> Result<DirEntryRef> {
        tracing::trace!("create file: {}", name.as_bstr());
        Self::init_children(inode)?;
        let data = inode.data.downcast_mut::<Self>().unwrap();

        if data.children.as_ref().unwrap().contains_key(&name) {
            return Err(errno::EEXIST);
        }

        let fs = inode.file_system.as_ref().ok_or(errno::EBADFD)?;
        let child = {
            let fs = fs.upgrade().ok_or(errno::EBADFD)?;
            let mut fs_ref = fs.borrow_mut();
            fs_ref.alloc_inode()?
        };
        child.borrow_mut().file_system = Some(fs.clone());

        let dir_entry = Rc::new(RefCell::new(DirEntry {
            name: name.clone(),
            inode: Rc::downgrade(&child),
            parent: Some(dir.clone()),
            mount: None,
        }));

        data.children.as_mut().unwrap().insert(name, child);
        Ok(dir_entry)
    }

    fn create_dir(inode: &mut Inode, dir: &DirEntryRef, name: FileName) -> Result<DirEntryRef> {
        let child = Self::create(inode, dir, name)?;
        {
            let inode = &child.borrow().inode.upgrade().ok_or(errno::ENOTDIR)?;
            inode.borrow_mut().kind = FileKind::Directory;
            inode.borrow_mut().data = Box::new(Self::empty());
            inode.borrow_mut().vtable = &HOST_DIRECTORY_VTABLE;
        }
        Ok(child)
    }

    fn create_file(inode: &mut Inode, dir: &DirEntryRef, name: FileName) -> Result<DirEntryRef> {
        let child = Self::create(inode, dir, name)?;
        {
            let inode = &child.borrow().inode.upgrade().ok_or(errno::ENOTDIR)?;
            inode.borrow_mut().kind = FileKind::RegularFile;
            inode.borrow_mut().data = Box::new(VirtualFile::new());
            inode.borrow_mut().vtable = &VIRTUAL_FILE_VTABLE;
        }
        Ok(child)
    }

    fn remove(inode: &mut Inode, _: &DirEntryRef, name: FileNameRef) -> Result<InodeRef> {
        tracing::trace!("remove file: {}", name.as_bstr());
        Self::init_children(inode)?;
        let data = inode.data.downcast_mut::<Self>().unwrap();

        match data.children.as_mut().unwrap().remove(name) {
            Some(inode) => {
                let links = Rc::strong_count(&inode) - 1;
                tracing::trace!("removed: {} ({} remaning links)", inode.borrow().index, links);
                Ok(inode)
            }
            None => Err(errno::EEXIST),
        }
    }

    #[allow(unused)]
    fn debug_children(&self) -> Vec<&bstr::BStr> {
        self.children.as_ref().unwrap().keys().map(|key| key.as_bstr()).collect()
    }
}

static HOST_DIRECTORY_VTABLE: InodeVtable = InodeVtable {
    create: VirtualDirectory::create,
    remove: VirtualDirectory::remove,
    iterate_dir: VirtualDirectory::iterate_dir,
    lookup: VirtualDirectory::lookup,
    create_dir: VirtualDirectory::create_dir,
    create_file: VirtualDirectory::create_file,
    ..DEFAULT_INODE_VTABLE
};

pub struct TempFs {
    /// The device number assigned to this file system.
    pub dev_id: usize,

    /// The inode number that will be assigned to the next file loaded.
    pub next_inode: usize,

    /// Keeps track of all inodes managed by this file system.
    pub inodes: HashMap<usize, std::rc::Weak<RefCell<Inode>>>,

    /// The root inode for the file system
    pub root: InodeRef,
}

impl TempFs {
    pub fn create(dev_id: usize) -> Rc<RefCell<Self>> {
        let root = Rc::new(RefCell::new(Inode::new(InodeIndex { dev: dev_id, ino: 0 })));
        let fs = Rc::new(RefCell::new(Self {
            dev_id,
            next_inode: 1,
            inodes: Some((0, Rc::downgrade(&root))).into_iter().collect(),
            root: root.clone(),
        }));

        let mut root = root.borrow_mut();
        root.file_system = Some(Rc::downgrade(&(fs.clone() as Rc<RefCell<dyn FileSystem>>)));
        root.data = Box::new(VirtualDirectory::empty());
        root.kind = FileKind::Directory;
        root.vtable = &HOST_DIRECTORY_VTABLE;

        fs
    }
}

impl FileSystem for TempFs {
    fn name(&self) -> &str {
        "tmpfs"
    }

    fn id(&self) -> usize {
        self.dev_id
    }

    fn alloc_inode(&mut self) -> Result<InodeRef> {
        let inner = Inode::new(InodeIndex { dev: self.dev_id, ino: self.next_inode });
        let inode = Rc::new(RefCell::new(inner));
        self.inodes.insert(self.next_inode, Rc::downgrade(&inode));

        self.next_inode += 1;
        Ok(inode)
    }

    fn remove_inode(&mut self, ino: usize) {
        tracing::trace!("inode removed: dev={}, ino={}", self.dev_id, ino);
        self.inodes.remove(&ino);
    }

    fn inode(&self, ino: usize) -> std::rc::Weak<RefCell<Inode>> {
        self.inodes.get(&ino).unwrap().clone()
    }
}

/// Map a host directory into a file-system
pub fn map_host(host_path: &std::path::Path, inode: &InodeRef) -> std::io::Result<()> {
    resolve_host_path(host_path, &mut inode.borrow_mut())?;
    Ok(())
}

/// Fill in metadata for `inode` by resolving the path at `host_path`.
fn resolve_host_path(host_path: &std::path::Path, inode: &mut Inode) -> std::io::Result<FileName> {
    use std::time::SystemTime;

    // Extract just the `file_name` component of the host path to use as the guest `file_name`
    let file_name = host_path.file_name().and_then(std::ffi::OsStr::to_str).unwrap_or("");
    let guest_path = file_name.as_bytes().to_owned();

    let elapsed_nanos = |time: std::io::Result<SystemTime>| -> i128 {
        let time = match time {
            Ok(time) => time,
            Err(_) => return 0,
        };
        if time < SystemTime::UNIX_EPOCH {
            -(SystemTime::UNIX_EPOCH.duration_since(time).unwrap().as_nanos() as i128)
        }
        else {
            time.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos() as i128
        }
    };

    let metadata = host_path.metadata()?;
    inode.modified = elapsed_nanos(metadata.modified());
    inode.created = elapsed_nanos(metadata.created());
    inode.accessed = elapsed_nanos(metadata.accessed());
    inode.size = metadata.len();

    inode.uid = 0;
    inode.gid = 0;
    inode.access = 0o777;

    if metadata.is_file() {
        inode.data = Box::new(LazyHostFile::load(host_path.to_path_buf()));
        inode.kind = FileKind::RegularFile;
        inode.vtable = &LAZY_FILE_VTABLE;
    }
    else if metadata.is_dir() {
        inode.data = Box::new(VirtualDirectory::load(host_path.to_path_buf())?);
        inode.kind = FileKind::Directory;
        inode.vtable = &HOST_DIRECTORY_VTABLE;
    }
    else {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid file"));
    };

    tracing::trace!("{} -> {} ({:?})", guest_path.as_bstr(), host_path.display(), inode.kind);

    Ok(guest_path)
}
