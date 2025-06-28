use std::{cell::RefCell, rc::Rc};

use icicle_cpu::mem::MemResult;

use crate::{
    errno,
    fs::{
        self, file, host::TempFs, FileKind, FileSystem, Inode, InodeRef, InodeVtable,
        DEFAULT_INODE_VTABLE,
    },
    LinuxMmu,
};

pub const AF_UNSPEC: u64 = 0;

/// Unix domain sockets (UDS).
pub const AF_UNIX: u64 = 1;

/// IPv4 socket.
pub const AF_INET: u64 = 2;

/// IPv6 socket.
pub const AF_INET6: u64 = 10;

/// Netlink socket (used for user space <-> kernel communication).
pub const AF_NETLINK: u64 = 16;

pub const SOCK_STREAM: u64 = 1;
pub const SOCK_DGRAM: u64 = 2;
pub const SOCK_RAW: u64 = 3;
pub const SOCK_RDM: u64 = 4;
pub const SOCK_SEQPACKET: u64 = 5;
pub const SOCK_DCCP: u64 = 6;

pub const SOCK_CLOEXEC: u64 = 0o02000000;
pub const SOCK_NONBLOCK: u64 = 0o00004000;

// @todo: checkme
pub const SOCKET_STORAGE_SIZE: usize = 64;

#[derive(Clone)]
pub struct SocketAddr {
    pub addr: [u8; SOCKET_STORAGE_SIZE],
}

impl SocketAddr {
    pub fn read_user<M: LinuxMmu>(mem: &mut M, addr: u64, len: u64) -> MemResult<Option<Self>> {
        if addr == 0 {
            return Ok(None);
        }

        let mut value = Self::default();
        let len = usize::min(len as usize, value.addr.len());
        mem.read_bytes(addr, &mut value.addr[..len])?;

        Ok(Some(value))
    }
}

impl Default for SocketAddr {
    fn default() -> Self {
        Self { addr: [0; SOCKET_STORAGE_SIZE] }
    }
}

pub struct Message<'a> {
    pub address: Option<&'a mut SocketAddr>,
    pub buf: &'a mut [u8],
}

static UNIX_DGRAM_VTABLE: InodeVtable =
    InodeVtable { recvfrom: UnixDgram::recvfrom, bind: UnixStream::bind, ..DEFAULT_INODE_VTABLE };

/// The maximum number of pending messages that we allow before we start overwritting data.
const MAX_QUEUED_DGRAMS: usize = 16;

#[derive(Clone, Default)]
pub struct UnixDgram {
    recv_index: usize,
    buf: [Vec<u8>; MAX_QUEUED_DGRAMS],
    socket_addr: SocketAddr,
}

impl UnixDgram {
    pub fn recvfrom(inode: &mut Inode, msg: &mut Message) -> fs::Result<usize> {
        let socket = inode.data.downcast_mut::<Self>().unwrap();

        // @fixme: zero length dgrams are allowed.
        if socket.buf[socket.recv_index].is_empty() {
            return Err(errno::EWOULDBLOCK);
        }

        let buf = &mut socket.buf[socket.recv_index];
        let len = usize::min(buf.len(), msg.buf.len());
        msg.buf[..len].copy_from_slice(&buf[..len]);
        buf.clear();

        socket.recv_index += 1;
        if socket.recv_index >= socket.buf.len() {
            socket.recv_index = 0;
        }

        Ok(len)
    }

    pub fn bind(inode: &mut Inode, addr: &SocketAddr) -> fs::Result<()> {
        let socket = inode.data.downcast_mut::<Self>().unwrap();
        socket.socket_addr = addr.clone();
        Ok(())
    }
}

static UNIX_STREAM_VTABLE: InodeVtable = InodeVtable {
    recvfrom: UnixStream::recvfrom,
    sendto: UnixStream::sendto,
    bind: UnixStream::bind,
    ..DEFAULT_INODE_VTABLE
};

#[derive(Clone, Default)]
pub struct UnixStream {
    stream: fs::Stream,
    socket_addr: SocketAddr,
}

impl UnixStream {
    pub fn recvfrom(inode: &mut Inode, msg: &mut Message) -> fs::Result<usize> {
        let socket = inode.data.downcast_mut::<Self>().unwrap();
        socket.stream.read(msg.buf)
    }

    pub fn sendto(inode: &mut Inode, msg: &Message) -> fs::Result<usize> {
        let socket = inode.data.downcast_mut::<Self>().unwrap();
        socket.stream.write(msg.buf)
    }

    pub fn bind(inode: &mut Inode, addr: &SocketAddr) -> fs::Result<()> {
        let socket = inode.data.downcast_mut::<Self>().unwrap();
        socket.socket_addr = addr.clone();
        Ok(())
    }
}

// @fixme: proper tcp sockets
pub type TcpSocket = UnixStream;

impl TcpSocket {
    pub fn recvfrom_tcp(_inode: &mut Inode, _msg: &mut Message) -> fs::Result<usize> {
        Err(errno::ENOTCONN)
    }

    pub fn sendto_tcp(_inode: &mut Inode, _msg: &Message) -> fs::Result<usize> {
        Err(errno::ENOTCONN)
    }
}

static TCP_SOCKET_VTABLE: InodeVtable = InodeVtable {
    recvfrom: TcpSocket::recvfrom_tcp,
    sendto: TcpSocket::sendto_tcp,
    ..UNIX_STREAM_VTABLE
};

// @fixme: proper UDP sockets
pub type UdpSocket = UnixDgram;

static UDP_SOCKET_VTABLE: InodeVtable = UNIX_DGRAM_VTABLE;

static NETLINK_VTABLE: InodeVtable = InodeVtable {
    recvfrom: |_, _| Err(errno::ENOSYS),
    sendto: |_, _| Err(errno::ENOSYS),
    ..UNIX_STREAM_VTABLE
};

pub struct SocketFs {
    fs: Rc<RefCell<TempFs>>,
}

impl SocketFs {
    pub fn create(dev_id: usize) -> Self {
        Self { fs: TempFs::create(dev_id) }
    }

    pub fn create_socket(&mut self, family: u64, kind: u64, protocol: u64) -> fs::Result<InodeRef> {
        macro_rules! af_not_supported {
            ($name:literal) => {{
                // tracing::warn!(concat!("Address family not supported {}", $name));
                return Err(errno::EAFNOSUPPORT);
            }};
        }

        match family {
            AF_UNSPEC => af_not_supported!("AF_UNSPEC"),
            AF_UNIX => self.create_unix_socket(kind, protocol),
            AF_INET => self.create_ipv4_socket(kind, protocol),
            AF_INET6 => af_not_supported!("AF_INET6"),
            AF_NETLINK => self.create_netlink_socket(kind, protocol),
            _ => af_not_supported!("Unknown"),
        }
    }

    fn create_unix_socket(&mut self, kind: u64, protocol: u64) -> fs::Result<InodeRef> {
        if protocol != AF_UNSPEC && protocol != AF_UNIX {
            return Err(errno::EPROTONOSUPPORT);
        }

        let (data, vtable): (Box<dyn std::any::Any>, &InodeVtable) = match kind {
            SOCK_STREAM => (Box::<UnixStream>::default(), &UNIX_STREAM_VTABLE),
            SOCK_DGRAM => (Box::<UnixDgram>::default(), &UNIX_DGRAM_VTABLE),
            _ => return Err(errno::ESOCKTNOSUPPORT),
        };

        self.create_socket_with(data, vtable)
    }

    fn create_ipv4_socket(&mut self, kind: u64, protocol: u64) -> fs::Result<InodeRef> {
        if protocol != 0 {
            return Err(errno::EPROTONOSUPPORT);
        }

        let (data, vtable): (Box<dyn std::any::Any>, &InodeVtable) = match kind {
            SOCK_STREAM => (Box::<TcpSocket>::default(), &TCP_SOCKET_VTABLE),
            SOCK_DGRAM => (Box::<UdpSocket>::default(), &UDP_SOCKET_VTABLE),
            _ => return Err(errno::ESOCKTNOSUPPORT),
        };

        self.create_socket_with(data, vtable)
    }

    // @fixme
    fn create_netlink_socket(&mut self, _kind: u64, _protocol: u64) -> fs::Result<InodeRef> {
        self.create_socket_with(Box::<UnixStream>::default(), &NETLINK_VTABLE)
    }

    fn create_socket_with(
        &mut self,
        data: Box<dyn std::any::Any>,
        vtable: &'static InodeVtable,
    ) -> fs::Result<InodeRef> {
        let inode = self.fs.borrow_mut().alloc_inode()?;
        {
            let mut inode = inode.borrow_mut();
            inode.data = data;
            inode.vtable = vtable;
            inode.kind = FileKind::Socket;
        }
        Ok(inode)
    }

    pub fn alloc_file(&mut self, inode: InodeRef) -> fs::Result<file::ActiveFile> {
        Ok(Rc::new(RefCell::new(file::ActiveFileData::new(vec![], inode))))
    }
}
