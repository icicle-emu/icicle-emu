//! File system for handling virtual devices

use std::rc::Rc;

use icicle_cpu::utils::XorShiftRng;

use crate::{errno, sys};

use super::{FileKind, Inode, InodeVtable, Result, DEFAULT_INODE_VTABLE};

pub fn map_device(inode: &mut Inode, device: Box<dyn Device>) {
    inode.kind = FileKind::CharacterDevice;
    inode.size = device.size();
    inode.data = Box::new(device);
    inode.vtable = &DEVICE_VTABLE;
}

static DEVICE_VTABLE: InodeVtable = InodeVtable {
    read: |inode, offset, buf| {
        let data = inode.data.downcast_mut::<Box<dyn Device>>().unwrap();
        data.read(offset, buf)
    },
    write: |inode, offset, buf| {
        let data = inode.data.downcast_mut::<Box<dyn Device>>().unwrap();
        data.write(offset, buf)
    },
    poll: |_inode, events| {
        // @fixme: allow devices to control whether they are ready or not.
        let mut revents = 0;
        if events & sys::poll::POLLIN != 0 {
            revents |= sys::poll::POLLIN;
        }
        if events & sys::poll::POLLOUT != 0 {
            revents |= sys::poll::POLLOUT;
        }
        revents
    },
    ..DEFAULT_INODE_VTABLE
};

#[allow(unused_variables)]
pub trait Device {
    fn read(&mut self, offset: usize, buf: &mut [u8]) -> Result<usize> {
        Err(errno::EPERM)
    }

    fn write(&mut self, offset: usize, buf: &[u8]) -> Result<usize> {
        Err(errno::EPERM)
    }

    fn size(&self) -> u64 {
        0
    }
}

impl Device for std::io::Cursor<Vec<u8>> {
    fn read(&mut self, offset: usize, buf: &mut [u8]) -> Result<usize> {
        self.set_position(offset as u64);
        std::io::Read::read(self, buf).map_err(|_| errno::EIO)
    }

    fn write(&mut self, _: usize, _: &[u8]) -> Result<usize> {
        Err(errno::EPERM)
    }

    fn size(&self) -> u64 {
        self.get_ref().len() as u64
    }
}

/// Represents a streaming device that is 'externally' connected. To support snapshotting, external
/// devices must maintain a copy of all bytes they have read and all bytes that have been written to
/// them in order to avoid repeating the same bytes externally.
#[derive(Clone)]
pub struct ExternalStream<T> {
    /// The number of bytes read from this device.
    pub read_offset: usize,

    /// A copy-on-write vector of all the bytes read from this device in any past snapshots.
    pub bytes_read: Rc<Vec<u8>>,

    /// The number of bytes written to this device.
    pub write_offset: usize,

    /// The maximum number of bytes written to this device.
    pub bytes_written: usize,

    /// The external device that we are wrapping.
    pub inner: T,
}

impl<T> ExternalStream<T> {
    pub fn new(inner: T) -> Self {
        Self {
            read_offset: 0,
            bytes_read: Rc::new(Vec::new()),
            write_offset: 0,
            bytes_written: 0,
            inner,
        }
    }
}

impl<T: Device + Clone + 'static> Device for ExternalStream<T> {
    fn read(&mut self, offset: usize, buf: &mut [u8]) -> Result<usize> {
        // Streams do not support reading from different offsets
        if offset != self.read_offset {
            return Err(errno::ESPIPE);
        }

        let count = match offset < self.bytes_read.len() {
            true => {
                let count = usize::min(self.bytes_read.len() - offset, buf.len());
                buf[..count].copy_from_slice(&self.bytes_read[offset..][..count]);
                count
            }
            false => {
                let count = self.inner.read(offset, buf)?;
                Rc::make_mut(&mut self.bytes_read).extend_from_slice(&buf[..count]);
                count
            }
        };

        self.read_offset += count;
        Ok(count)
    }

    fn write(&mut self, offset: usize, buf: &[u8]) -> Result<usize> {
        // Streams do not support writing to different offsets
        if offset != self.write_offset {
            return Err(errno::ESPIPE);
        }

        let count = match offset < self.bytes_written {
            true => usize::min(self.bytes_written - offset, buf.len()),
            false => self.inner.write(offset, buf)?,
        };

        self.bytes_written += count;
        Ok(count)
    }
}

pub struct ReadOnlyDevice<T>(pub T);

impl<T: std::io::Read + 'static> Device for ReadOnlyDevice<T> {
    fn read(&mut self, _: usize, buf: &mut [u8]) -> Result<usize> {
        match std::io::Read::read(&mut self.0, buf) {
            Ok(count) => Ok(count),
            Err(_) => Err(errno::EIO),
        }
    }
}

pub struct WriteOnlyDevice<T: std::io::Write>(pub T);

impl<T: std::io::Write + 'static> Device for WriteOnlyDevice<T> {
    fn write(&mut self, _: usize, buf: &[u8]) -> Result<usize> {
        match std::io::Write::write(&mut self.0, buf) {
            Ok(count) => Ok(count),
            Err(_) => Err(errno::EIO),
        }
    }
}

#[derive(Clone)]
pub struct ReadOnlySlice<T: AsRef<[u8]>>(pub T);

impl ReadOnlySlice<Vec<u8>> {
    pub fn from_vec(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn from_path(path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        Ok(Self::from_vec(std::fs::read(path)?))
    }
}

impl<T> Device for ReadOnlySlice<T>
where
    T: AsRef<[u8]>,
{
    fn read(&mut self, offset: usize, buf: &mut [u8]) -> Result<usize> {
        let data = self.0.as_ref();

        if offset >= data.len() {
            return Ok(0);
        }

        let len = usize::min(data.len() - offset, buf.len());
        buf[..len].copy_from_slice(&data[offset..offset + len]);

        Ok(len)
    }

    fn write(&mut self, _offset: usize, _buf: &[u8]) -> Result<usize> {
        Err(errno::EPERM)
    }

    fn size(&self) -> u64 {
        self.0.as_ref().len() as u64
    }
}

#[derive(Clone, Default)]
pub struct SharedBufDevice {
    buf: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

impl SharedBufDevice {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&self) -> Result<()> {
        let mut lock = self.buf.lock().map_err(|_| errno::EIO)?;
        lock.clear();
        Ok(())
    }

    pub fn data(&self) -> Result<Vec<u8>> {
        let lock = self.buf.lock().map_err(|_| errno::EIO)?;
        Ok(lock.clone())
    }

    pub fn set(&self, data: &[u8]) -> Result<()> {
        let mut lock = self.buf.lock().map_err(|_| errno::EIO)?;
        lock.clear();
        lock.extend_from_slice(data);
        Ok(())
    }
}

impl Device for SharedBufDevice {
    fn read(&mut self, offset: usize, buf: &mut [u8]) -> Result<usize> {
        let data = self.buf.lock().map_err(|_| errno::EIO)?;

        if offset >= data.len() {
            return Ok(0);
        }

        let len = usize::min(data.len() - offset, buf.len());
        buf[..len].copy_from_slice(&data[offset..offset + len]);

        Ok(len)
    }

    fn write(&mut self, _: usize, buf: &[u8]) -> Result<usize> {
        let mut lock = self.buf.lock().map_err(|_| errno::EIO)?;
        lock.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn size(&self) -> u64 {
        self.buf.as_ref().lock().map_or(0, |x| x.len() as u64)
    }
}

#[derive(Default, Clone)]
pub struct DeviceData {
    /// The bytes associated with the device
    pub data: Vec<u8>,
    /// A list of (offset, length) pairs, recording where `read` calls have been made.
    pub reads: Vec<(u64, u64)>,
}

/// Like `SharedBufDevice`, but also records read offsets.
#[derive(Clone, Default)]
pub struct ReadableSharedBufDevice {
    data: std::sync::Arc<std::sync::Mutex<DeviceData>>,
}

impl ReadableSharedBufDevice {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&self) -> Result<()> {
        let mut lock = self.data.lock().map_err(|_| errno::EIO)?;
        lock.data.clear();
        lock.reads.clear();
        Ok(())
    }

    pub fn read_positions(&self) -> Result<Vec<(u64, u64)>> {
        let lock = self.data.lock().map_err(|_| errno::EIO)?;
        Ok(lock.reads.clone())
    }

    pub fn set(&self, data: &[u8]) -> Result<()> {
        let mut lock = self.data.lock().map_err(|_| errno::EIO)?;
        lock.data.clear();
        lock.data.extend_from_slice(data);
        lock.reads.clear();
        Ok(())
    }
}

impl Device for ReadableSharedBufDevice {
    fn read(&mut self, offset: usize, buf: &mut [u8]) -> Result<usize> {
        let mut lock = self.data.lock().map_err(|_| errno::EIO)?;
        lock.reads.push((offset as u64, buf.len() as u64));
        let data = &lock.data;

        if offset >= data.len() {
            return Ok(0);
        }

        let len = usize::min(data.len() - offset, buf.len());
        buf[..len].copy_from_slice(&data[offset..offset + len]);

        Ok(len)
    }

    fn write(&mut self, _: usize, _buf: &[u8]) -> Result<usize> {
        Err(errno::EPERM)
    }

    fn size(&self) -> u64 {
        self.data.lock().map_or(0, |x| x.data.len() as u64)
    }
}

/// A device that behaves like `/dev/null`.
pub struct NullDevice;

impl Device for NullDevice {
    fn read(&mut self, _: usize, _: &mut [u8]) -> Result<usize> {
        Ok(0)
    }

    fn write(&mut self, _: usize, buf: &[u8]) -> Result<usize> {
        Ok(buf.len())
    }
}

/// A device that behaves like `/dev/zero`.
pub struct ZeroDevice;

impl Device for ZeroDevice {
    fn read(&mut self, _: usize, buf: &mut [u8]) -> Result<usize> {
        buf.fill(0);
        Ok(buf.len())
    }

    fn write(&mut self, _: usize, buf: &[u8]) -> Result<usize> {
        Ok(buf.len())
    }
}

/// A device that always generates an error on read/write
pub struct ErrorDevice(pub super::Errno);

impl Device for ErrorDevice {
    fn read(&mut self, _: usize, _: &mut [u8]) -> Result<usize> {
        Err(self.0)
    }

    fn write(&mut self, _: usize, _: &[u8]) -> Result<usize> {
        Err(self.0)
    }

    fn size(&self) -> u64 {
        1
    }
}

/// A device that behaves like `/dev/urandom`.
pub struct RandomDevice {
    rng: XorShiftRng,
}

impl RandomDevice {
    pub fn new(seed: u64) -> Self {
        Self { rng: XorShiftRng::new(seed) }
    }
}

impl Device for RandomDevice {
    fn read(&mut self, _: usize, buf: &mut [u8]) -> Result<usize> {
        self.rng.fill_bytes(buf);
        Ok(buf.len())
    }

    fn write(&mut self, _: usize, buf: &[u8]) -> Result<usize> {
        Ok(buf.len())
    }

    fn size(&self) -> u64 {
        0
    }
}
