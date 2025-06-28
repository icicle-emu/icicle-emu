// @fixme: unify IoVec handling.
// @fixme: improve file handling.
// @fixme: avoid excess allocations during syscalls.
// @fixme: handle non-blocking file handles.

use bstr::ByteSlice;

use icicle_cpu::{
    mem::{self, perm, AllocLayout, MemResult},
    utils::{align_down, align_up},
    ExceptionCode, VmExit,
};

use crate::{
    arch::{self, CDataType},
    errno,
    fs::{self, PathRef},
    sys,
    types::{self, IoVec, Seek, SemBuf, Timespec, Timeval, Timezone},
    CloneState, Kernel, LinuxCpu, LinuxMmu, LinuxResult, MemMappedFile, SemaphoreSet,
    SemaphoreSetUndo, Shmem, TerminationReason,
};

pub type Call0<C> = fn(&mut Ctx<C>) -> LinuxResult;
pub type Call1<C> = fn(&mut Ctx<C>, u64) -> LinuxResult;
pub type Call2<C> = fn(&mut Ctx<C>, u64, u64) -> LinuxResult;
pub type Call3<C> = fn(&mut Ctx<C>, u64, u64, u64) -> LinuxResult;
pub type Call4<C> = fn(&mut Ctx<C>, u64, u64, u64, u64) -> LinuxResult;
pub type Call5<C> = fn(&mut Ctx<C>, u64, u64, u64, u64, u64) -> LinuxResult;
pub type Call6<C> = fn(&mut Ctx<C>, u64, u64, u64, u64, u64, u64) -> LinuxResult;

pub fn get_syscall_handler<C: LinuxCpu>(syscall_number: u64) -> crate::arch::Handler<C> {
    use crate::{arch::Handler, sys::syscall as sys};
    include!(concat!(env!("OUT_DIR"), "/syscall_dispatcher.rs"))
}

pub fn handle_syscall<C: LinuxCpu>(kernel: &mut Kernel, cpu: &mut C, id: u64) -> LinuxResult {
    use crate::arch::Handler;

    let mut ctx = Ctx { cpu, kernel };

    macro_rules! invoke {
        ($n:expr, $handler:expr) => {
            do_syscall::<C, _, $n>(&mut ctx, $handler)
        };
    }

    match get_syscall_handler::<C>(id) {
        Handler::_0(f) => invoke!(1, |ctx, _| f(ctx)),
        Handler::_1(f) => invoke!(2, |ctx, a| f(ctx, a[1])),
        Handler::_2(f) => invoke!(3, |ctx, a| f(ctx, a[1], a[2])),
        Handler::_3(f) => invoke!(4, |ctx, a| f(ctx, a[1], a[2], a[3])),
        Handler::_4(f) => invoke!(5, |ctx, a| f(ctx, a[1], a[2], a[3], a[4])),
        Handler::_5(f) => invoke!(6, |ctx, a| f(ctx, a[1], a[2], a[3], a[4], a[5])),
        Handler::_6(f) => invoke!(7, |ctx, a| f(ctx, a[1], a[2], a[3], a[4], a[5], a[6])),
    }
}

/// Read `count` bytes from userspace starting at `addr` into `buf` returning a slice contining
/// the read bytes, or an error if any address is unreadable
pub fn read_user<'a, M: LinuxMmu>(
    mem: &mut M,
    addr: u64,
    count: usize,
    buf: &'a mut Vec<u8>,
) -> MemResult<&'a [u8]> {
    let start = buf.len();
    buf.resize(start + count, 0);
    mem.read_bytes(addr, &mut buf[start..])?;
    Ok(&buf[start..])
}

macro_rules! syscall_warn {
    ($msg:literal $(,)?) => {
        tracing::warn!($msg)
    };
    ($fmt:expr, $($arg:tt)*) => {
        tracing::warn!($fmt, $($arg)*)
    };
}

macro_rules! ensure {
    ($cond:expr) => {
        if !$cond {
            return Err(errno::EINVAL.into());
        }
    };
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            syscall_warn!($msg);
            return Err(errno::EINVAL.into());
        }
    };
    ($cond:expr, $fmt:expr, $($arg:tt)*) => {
        if !$cond {
            syscall_warn!($fmt, $($arg)*);
            return Err(errno::EINVAL.into());
        }
    };

}

pub struct Ctx<'cpu, C: LinuxCpu> {
    pub cpu: &'cpu mut C,
    pub kernel: &'cpu mut Kernel,
}

impl<'cpu, C: LinuxCpu> Ctx<'cpu, C> {
    fn get_arg(&mut self, n: usize) -> LinuxResult {
        self.kernel.arch.dynamic.get_arg(self.cpu, n)
    }

    fn read_user_struct<T: arch::Struct>(&mut self, addr: u64) -> MemResult<T> {
        self.kernel.arch.libc(addr).read_struct(self.cpu.mem())
    }

    fn write_user_struct<T>(&mut self, addr: u64, value: &T) -> MemResult<()>
    where
        T: arch::Struct,
    {
        self.kernel.arch.libc(addr).write_struct(self.cpu.mem(), value)
    }
}

#[inline]
fn do_syscall<C, F, const N: usize>(ctx: &mut Ctx<C>, handler: F) -> LinuxResult
where
    C: LinuxCpu,
    F: FnOnce(&mut Ctx<C>, [u64; N]) -> LinuxResult,
{
    let args: [u64; N] = ctx.kernel.arch.dynamic.get_args(ctx.cpu)?;
    let result = handler(ctx, args);

    tracing::debug!("{}", SyscallFormatter {
        src: CallSource::new(ctx.cpu, ctx.kernel),
        args: &args,
        result,
        show_id: true,
        trace_i_count: ctx.kernel.trace_i_count,
    });

    result
}

struct CallSource<'a> {
    #[allow(unused)]
    id: u64,
    name: &'a str,
    pid: u64,
    i_count: u64,
}

impl<'a> CallSource<'a> {
    fn new<C: LinuxCpu>(cpu: &mut C, kernel: &'a Kernel) -> Self {
        let id = kernel.arch.dynamic.get_arg(cpu, 0).unwrap();
        let name = kernel.arch.get_syscall_name(cpu);
        Self { id, name, pid: kernel.process.pid, i_count: cpu.i_count() }
    }
}

struct SyscallFormatter<'a> {
    src: CallSource<'a>,
    args: &'a [u64],
    result: LinuxResult,
    show_id: bool,
    trace_i_count: bool,
}

impl std::fmt::Display for SyscallFormatter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.trace_i_count {
            write!(f, "[{}, pid={}] ", self.src.i_count, self.src.pid)?
        }
        if self.show_id {
            write!(f, "{}: ", self.src.id)?;
        }
        write!(f, "{}({:0x?}) = {}", self.src.name, &self.args[1..], FmtResult(self.result))
    }
}

struct FmtResult(LinuxResult);

impl std::fmt::Display for FmtResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Ok(value) => write!(f, "{:#0x}", value),
            Err(crate::LinuxError::Error(errno)) => {
                write!(f, "{} ({})", errno::errno_str(errno), errno)
            }
            Err(crate::LinuxError::VmExit(exit)) => write!(f, "? Exit({:0x?})", exit),
        }
    }
}

pub const NULL_PTR: u64 = 0;

pub fn unimplemented<C: LinuxCpu>(ctx: &mut Ctx<C>) -> LinuxResult {
    let id = ctx.get_arg(0)?;
    let name = ctx.kernel.arch.get_syscall_name(ctx.cpu);
    tracing::warn!("Unimplemented syscall: {id} ({name})");
    Err(errno::ENOSYS.into())
}

pub fn ignore<C: LinuxCpu>(ctx: &mut Ctx<C>) -> LinuxResult {
    let id = ctx.get_arg(0)?;
    let name = ctx.kernel.arch.get_syscall_name(ctx.cpu);
    tracing::warn!("Ignored syscall: {id} ({name})");
    Ok(0)
}

pub fn read<C: LinuxCpu>(ctx: &mut Ctx<C>, fd: u64, buf: u64, count: u64) -> LinuxResult {
    // Read the bytes from the file into a temporary buffer
    let mut tmp = std::mem::take(&mut ctx.kernel.buffer);
    let start = tmp.len();
    tmp.resize(start + count as usize, 0);

    let file = ctx.kernel.get_file(fd)?;
    let read_bytes = file.borrow_mut().read(&mut tmp)?;

    // Write buffer to userspace
    ctx.cpu.mem().write_bytes(buf, &tmp[start..start + read_bytes])?;
    ctx.kernel.buffer = tmp;

    // Return the number of bytes read from the file
    Ok(read_bytes as u64)
}

pub fn readv<C: LinuxCpu>(ctx: &mut Ctx<C>, fd: u64, iov: u64, iovcnt: u64) -> LinuxResult {
    let mut total = 0;
    let mut reader = ctx.kernel.arch.libc(iov);
    for _ in 0..iovcnt {
        let iov = reader.read_struct::<IoVec, _>(ctx.cpu.mem())?;
        let (base, len) = (iov.base.value, iov.len.value);

        let read_bytes = read(ctx, fd, base, len)?;
        total += read_bytes;

        if read_bytes < len {
            break;
        }
    }
    Ok(total)
}

pub fn pread64<C: LinuxCpu>(
    ctx: &mut Ctx<C>,
    fd: u64,
    buf: u64,
    count: u64,
    offset: u64,
) -> LinuxResult {
    lseek(ctx, fd, offset, Seek::Set as u64)?;
    read(ctx, fd, buf, count)
}

pub fn write<C: LinuxCpu>(ctx: &mut Ctx<C>, fd: u64, buf: u64, count: u64) -> LinuxResult {
    // Read buffer from userspace into kernel buffer
    let mut tmp = std::mem::take(&mut ctx.kernel.buffer);
    let start = tmp.len();
    read_user(ctx.cpu.mem(), buf, count as usize, &mut tmp)?;

    // Write content of kernel buffer to file
    let file = ctx.kernel.get_file(fd)?;
    let written_bytes = file.borrow_mut().write(&tmp[start..])?;
    ctx.kernel.buffer = tmp;

    Ok(written_bytes as u64)
}

pub fn writev<C: LinuxCpu>(ctx: &mut Ctx<C>, fd: u64, iov: u64, iovcnt: u64) -> LinuxResult {
    let mut total_written = 0;
    let mut reader = ctx.kernel.arch.libc(iov);
    for _ in 0..iovcnt {
        let iov = reader.read_struct::<IoVec, _>(ctx.cpu.mem())?;
        let (base, len) = (iov.base.value, iov.len.value);

        tracing::trace!("write: base={:#0x}, count={:#0x}", base, len);
        let written = write(ctx, fd, base, len)?;
        total_written += written;
        if written < len {
            break;
        }
    }
    Ok(total_written)
}

pub fn open<C: LinuxCpu>(ctx: &mut Ctx<C>, pathname: u64, flags: u64, _mode: u64) -> LinuxResult {
    let flags = fs::OpenFlags::from_bits(flags).ok_or(errno::EINVAL)?;

    let path_buf: &[u8] =
        ctx.kernel.arch.libc(pathname).read_cstr(ctx.cpu.mem(), &mut ctx.kernel.buffer)?;
    let file = ctx.kernel.vfs.open_at(&ctx.kernel.process.cwd(), path_buf, flags)?;
    let fd = ctx.kernel.process.file_table.add(file);
    tracing::trace!("opened: {} as fd={}", path_buf.as_bstr(), fd);
    Ok(fd)
}

pub fn openat<C: LinuxCpu>(
    ctx: &mut Ctx<C>,
    dirfd: u64,
    pathname: u64,
    flags: u64,
    mode: u64,
) -> LinuxResult {
    const AT_FDCWD: i32 = -100_i32;

    if dirfd as u32 as i32 == AT_FDCWD {
        return open(ctx, pathname, flags, mode);
    }

    tracing::warn!("file descriptor relative `openat` not supported");
    Err(errno::ENOSYS.into())
}

pub fn close<C: LinuxCpu>(ctx: &mut Ctx<C>, fd: u64) -> LinuxResult {
    ctx.kernel.process.file_table.close(&mut ctx.kernel.process_manager, fd)?;
    Ok(0)
}

pub fn unlink<C: LinuxCpu>(ctx: &mut Ctx<C>, pathname: u64) -> LinuxResult {
    let path_buf: &[u8] =
        ctx.kernel.arch.libc(pathname).read_cstr(ctx.cpu.mem(), &mut ctx.kernel.buffer)?;
    ctx.kernel.vfs.unlink_at(&ctx.kernel.process.cwd(), path_buf)?;
    Ok(0)
}

pub fn fadvise64<C: LinuxCpu>(
    _ctx: &mut Ctx<C>,
    _fd: u64,
    _advice: u64,
    _offset: u64,
    _len: u64,
) -> LinuxResult {
    // This is just a hint, we don't need to do anything.
    Ok(0)
}

pub fn dup<C: LinuxCpu>(ctx: &mut Ctx<C>, oldfd: u64) -> LinuxResult {
    // @fixme: new file descriptor should not share flags.
    let file = ctx.kernel.process.file_table.get(&mut ctx.kernel.process_manager, oldfd)?;
    Ok(ctx.kernel.process.file_table.add(file))
}

pub fn dup2<C: LinuxCpu>(ctx: &mut Ctx<C>, oldfd: u64, newfd: u64) -> LinuxResult {
    // @fixme: new file descriptor should not share flags.
    let file = ctx.kernel.process.file_table.get(&mut ctx.kernel.process_manager, oldfd)?;
    if oldfd == newfd {
        return Ok(newfd);
    }
    ctx.kernel.process.file_table.set(&mut ctx.kernel.process_manager, newfd, file);
    Ok(newfd)
}

pub fn dup3<C: LinuxCpu>(ctx: &mut Ctx<C>, oldfd: u64, newfd: u64, _flags: u64) -> LinuxResult {
    // @fixme: update flags for descriptor.
    dup2(ctx, oldfd, newfd)
}

pub fn pipe_m<C: LinuxCpu>(ctx: &mut Ctx<C>) -> LinuxResult {
    let inode = ctx.kernel.vfs.pipefs.create_pipe()?;

    let fd0 = {
        let file = ctx.kernel.vfs.pipefs.alloc_file(inode.clone())?;
        ctx.kernel.process.file_table.add(file)
    };
    let fd1 = {
        let file = ctx.kernel.vfs.pipefs.alloc_file(inode)?;
        ctx.kernel.process.file_table.add(file)
    };

    // This has a special calling convention on mips.
    let v1 = ctx.cpu.sleigh().get_reg("v1").unwrap().var;
    ctx.cpu.write_var(v1, fd1);

    Ok(fd0)
}

pub fn socket<C: LinuxCpu>(ctx: &mut Ctx<C>, domain: u64, kind: u64, protocol: u64) -> LinuxResult {
    let inode = ctx.kernel.vfs.sockfs.create_socket(domain, kind, protocol)?;
    let file = ctx.kernel.vfs.sockfs.alloc_file(inode)?;
    let fd = ctx.kernel.process.file_table.add(file);
    Ok(fd)
}

pub fn bind<C: LinuxCpu>(ctx: &mut Ctx<C>, sockfd: u64, addr: u64, addrlen: u64) -> LinuxResult {
    let mut sockaddr = fs::socket::SocketAddr::default();
    if addrlen as usize > sockaddr.addr.len() {
        return Err(errno::EINVAL.into());
    }

    ctx.cpu.mem().read_bytes(addr, &mut sockaddr.addr[..addrlen as usize])?;

    let file = ctx.kernel.process.file_table.get(&mut ctx.kernel.process_manager, sockfd)?;
    file.borrow_mut().bind(&sockaddr)?;

    Ok(0)
}

fn do_send<C: LinuxCpu>(
    ctx: &mut Ctx<C>,
    file: &fs::ActiveFile,
    address: Option<&mut fs::socket::SocketAddr>,
    buf: u64,
    len: u64,
) -> LinuxResult {
    ctx.kernel.buffer.clear();
    ctx.kernel.buffer.resize(len as usize, 0);
    ctx.cpu.mem().read_bytes(buf, &mut ctx.kernel.buffer)?;

    let msg = fs::socket::Message { address, buf: &mut ctx.kernel.buffer };
    Ok(file.borrow_mut().sendto(&msg)? as u64)
}

pub fn sendto<C: LinuxCpu>(
    ctx: &mut Ctx<C>,
    sockfd: u64,
    buf: u64,
    len: u64,
    _flags: u64,
    dst_addr: u64,
    addrlen: u64,
) -> LinuxResult {
    let file = ctx.kernel.process.file_table.get(&mut ctx.kernel.process_manager, sockfd)?;
    let mut sock_addr = fs::socket::SocketAddr::read_user(ctx.cpu.mem(), dst_addr, addrlen)?;

    match do_send(ctx, &file, sock_addr.as_mut(), buf, len) {
        Ok(bytes) => Ok(bytes),
        Err(crate::LinuxError::Error(errno::EWOULDBLOCK)) => {
            file.borrow_mut().listeners.insert(ctx.kernel.process.pid);
            ctx.kernel.switch_task(ctx.cpu, crate::PauseReason::WaitFile)
        }
        Err(e) => Err(e),
    }
}

pub fn sendmsg<C: LinuxCpu>(ctx: &mut Ctx<C>, socket: u64, msg: u64, _flags: u64) -> LinuxResult {
    let msg = ctx.read_user_struct::<types::MsgHdr>(msg)?;
    let file = ctx.kernel.process.file_table.get(&mut ctx.kernel.process_manager, socket)?;

    let mut sock_addr =
        fs::socket::SocketAddr::read_user(ctx.cpu.mem(), msg.name.value, msg.namelen.value)?;

    let mut total_written = 0;
    let mut reader = ctx.kernel.arch.libc(msg.iov.value);
    for _ in 0..msg.iovlen.value {
        let iov = reader.read_struct::<IoVec, _>(ctx.cpu.mem())?;
        let (base, len) = (iov.base.value, iov.len.value);

        match do_send(ctx, &file, sock_addr.as_mut(), base, len) {
            Ok(bytes) => total_written += bytes,
            Err(crate::LinuxError::Error(errno::EWOULDBLOCK)) => {
                if total_written == 0 {
                    file.borrow_mut().listeners.insert(ctx.kernel.process.pid);
                    return ctx.kernel.switch_task(ctx.cpu, crate::PauseReason::WaitFile);
                }
                break;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(total_written)
}

fn do_recv<C: LinuxCpu>(
    ctx: &mut Ctx<C>,
    file: &fs::ActiveFile,
    address: Option<&mut fs::socket::SocketAddr>,
    buf: u64,
    len: u64,
) -> LinuxResult {
    ctx.kernel.buffer.clear();
    ctx.kernel.buffer.resize(len as usize, 0);

    let mut msg = fs::socket::Message { address, buf: &mut ctx.kernel.buffer };
    let read_bytes = file.borrow_mut().recvfrom(&mut msg)?;
    ctx.cpu.mem().write_bytes(buf, &msg.buf[..read_bytes])?;

    Ok(read_bytes as u64)
}

pub fn recvfrom<C: LinuxCpu>(
    ctx: &mut Ctx<C>,
    sockfd: u64,
    buf: u64,
    len: u64,
    _flags: u64,
    src_addr: u64,
    addrlen: u64,
) -> LinuxResult {
    let file = ctx.kernel.process.file_table.get(&mut ctx.kernel.process_manager, sockfd)?;
    let mut sock_addr = (src_addr != NULL_PTR).then(fs::socket::SocketAddr::default);

    let read_bytes = match do_recv(ctx, &file, sock_addr.as_mut(), buf, len) {
        Ok(bytes) => bytes,
        Err(crate::LinuxError::Error(errno::EWOULDBLOCK)) => {
            file.borrow_mut().listeners.insert(ctx.kernel.process.pid);
            return ctx.kernel.switch_task(ctx.cpu, crate::PauseReason::WaitFile);
        }
        Err(e) => return Err(e),
    };

    if let Some(addr) = sock_addr {
        let len = usize::min(addrlen as usize, addr.addr.len());
        ctx.cpu.mem().write_bytes(src_addr, &addr.addr[..len])?;
    }

    Ok(read_bytes)
}

pub fn recvmsg<C: LinuxCpu>(ctx: &mut Ctx<C>, socket: u64, msg: u64, _flags: u64) -> LinuxResult {
    let msg = ctx.read_user_struct::<types::MsgHdr>(msg)?;
    let file = ctx.kernel.process.file_table.get(&mut ctx.kernel.process_manager, socket)?;

    let mut sock_addr = (msg.name.value != NULL_PTR).then(fs::socket::SocketAddr::default);

    let mut total_read = 0;
    let mut reader = ctx.kernel.arch.libc(msg.iov.value);
    for _ in 0..msg.iovlen.value {
        let iov = reader.read_struct::<IoVec, _>(ctx.cpu.mem())?;
        let (base, len) = (iov.base.value, iov.len.value);

        match do_recv(ctx, &file, sock_addr.as_mut(), base, len) {
            Ok(bytes) => total_read += bytes,
            Err(crate::LinuxError::Error(errno::EWOULDBLOCK)) => {
                if total_read == 0 {
                    file.borrow_mut().listeners.insert(ctx.kernel.process.pid);
                    return ctx.kernel.switch_task(ctx.cpu, crate::PauseReason::WaitFile);
                }
                break;
            }
            Err(e) => return Err(e),
        }
    }

    if let Some(addr) = sock_addr {
        let len = usize::min(msg.namelen.value as usize, addr.addr.len());
        ctx.cpu.mem().write_bytes(msg.name.value, &addr.addr[..len])?;
    }

    Ok(total_read)
}

pub fn ppoll<C: LinuxCpu>(
    _ctx: &mut Ctx<C>,
    _fds: u64,
    _nfds: u64,
    _timeout_ts: u64,
    _sigmask: u64,
) -> LinuxResult {
    // TODO: handle this properly
    Ok(0)
}

pub fn poll<C: LinuxCpu>(ctx: &mut Ctx<C>, fds: u64, nfds: u64, timeout: u64) -> LinuxResult {
    let mut ready_fds = 0;

    let mut reader = ctx.kernel.arch.libc(fds);
    for _ in 0..nfds {
        let mut writer = reader.clone();
        let mut entry: types::PollFd = reader.read_struct(ctx.cpu.mem())?;

        let fd = entry.fd.value;
        let events = entry.events.value;

        let file = ctx
            .kernel
            .process
            .file_table
            .get(&mut ctx.kernel.process_manager, fd)
            .map_err(|_| sys::poll::POLLNVAL)?;
        let revents = file.borrow_mut().poll(events)?;

        if revents != 0 {
            ready_fds += 1
        }
        tracing::trace!("poll(fd={}, events={:#0x}, revents={:#0x})", fd, events, revents);

        entry.revents.value = revents;
        writer.write_struct(ctx.cpu.mem(), &entry)?;
    }

    finish_poll(ctx, ready_fds, Some(timeout))
}

fn finish_poll<C: LinuxCpu>(
    ctx: &mut Ctx<C>,
    ready_count: u64,
    timeout: Option<u64>,
) -> LinuxResult {
    // @fixme: remove listeners on resume and inspect this list
    ctx.kernel.process.file_events.clear();

    if ready_count == 0 && timeout != Some(0) {
        if ctx.kernel.process.timeout.is_some() {
            // If the process was resumed, and we reached this stage without any other events then
            // assume the timeout expired.
            return Ok(0);
        }

        // Otherwise the process will block.
        ctx.kernel.process.timeout = timeout.map(std::time::Duration::from_millis);
        return ctx.kernel.switch_task(ctx.cpu, crate::PauseReason::WaitFile);
    }
    Ok(ready_count)
}

pub fn select<C: LinuxCpu>(
    ctx: &mut Ctx<C>,
    n: u64,
    readfds: u64,
    writefds: u64,
    exceptfds: u64,
    timeout: u64,
) -> LinuxResult {
    // const FD_SETSIZE: u64 = 1024;

    if n == 0 {
        return Err(errno::EINVAL.into());
    }

    if exceptfds != NULL_PTR {
        // @fixme: we don't support monitoring "exceptional conditions"
        return Err(errno::ENOSYS.into());
    }

    if writefds != NULL_PTR {
        // @fixme: we don't support monitoring write event
        return Err(errno::ENOSYS.into());
    }

    let timeout = match timeout {
        NULL_PTR => None,
        addr => Some(ctx.read_user_struct::<types::libc::intptr_t>(addr)?.value),
    };

    let fd_limit = u64::min(n, ctx.kernel.process.file_table.files.len() as u64);
    let long_size = ctx.kernel.arch.triple.data_model().unwrap().long_size();
    let long_bytes = long_size.bytes() as usize;

    let fds_count = align_up(fd_limit, long_size.bits() as u64) / long_size.bits() as u64;

    // Read long aligned bit masks from `readfds` to the kernel buffer in LE format.
    ctx.kernel.buffer.clear();
    let mut reader = ctx.kernel.arch.libc(readfds);
    for _ in 0..fds_count {
        let value = reader.read::<arch::ULong, _>(ctx.cpu.mem())?;
        ctx.kernel.buffer.extend_from_slice(&value.to_le_bytes()[..long_bytes]);
    }

    let mut ready_count = 0;
    tracing::debug!("readfds = {}", icicle_cpu::utils::hex(&ctx.kernel.buffer));
    for (byte_idx, byte) in ctx.kernel.buffer.iter_mut().enumerate() {
        for bit_idx in 0..8 {
            let bit = 1 << bit_idx;
            if *byte & bit == 0 {
                continue;
            }
            *byte &= !bit;

            let fd = (byte_idx * 8 + bit_idx) as u64;
            let file = ctx.kernel.process.file_table.get(&mut ctx.kernel.process_manager, fd)?;

            let revents = file.borrow_mut().poll(sys::poll::POLLIN)?;

            if revents & sys::poll::POLLIN != 0 {
                ready_count += 1;
                *byte |= bit;
            }

            // @todo: check write
        }
    }

    let result = finish_poll(ctx, ready_count, timeout)?;

    let mut writer = ctx.kernel.arch.libc(readfds);
    for chunk in ctx.kernel.buffer.chunks(long_bytes) {
        let mut long = [0; 8];
        long[..long_bytes].copy_from_slice(chunk);
        writer.write::<arch::ULong, _>(ctx.cpu.mem(), u64::from_le_bytes(long))?;
    }

    Ok(result)
}

pub fn pselect<C: LinuxCpu>(
    _ctx: &mut Ctx<C>,
    n: u64,
    _readfds: u64,
    _writefds: u64,
    _exceptfds: u64,
    _timeout: u64,
    _sigmask: u64,
) -> LinuxResult {
    if n == 0 {
        return Err(errno::EINVAL.into());
    }

    if n != 1 {
        // @fixme: we don't support more than one file descriptor
        return Err(errno::ENOSYS.into());
    }

    Ok(1)
}

pub fn access<C: LinuxCpu>(ctx: &mut Ctx<C>, pathname: u64, mode: u64) -> LinuxResult {
    // @fixme: check mode
    let _ = mode;
    let path_buf: &[u8] =
        ctx.kernel.arch.libc(pathname).read_cstr(ctx.cpu.mem(), &mut ctx.kernel.buffer)?;
    ctx.kernel.vfs.resolve(ctx.kernel.process.cwd(), path_buf)?;
    Ok(0)
}

pub fn readlinkat<C: LinuxCpu>(
    ctx: &mut Ctx<C>,
    dirfd: u64,
    pathname: u64,
    _buf: u64,
    _bufsiz: u64,
) -> LinuxResult {
    const AT_FDCWD: i32 = -100_i32;

    let path_buf: &[u8] =
        ctx.kernel.arch.libc(pathname).read_cstr(ctx.cpu.mem(), &mut ctx.kernel.buffer)?;

    if dirfd as u32 as i32 == AT_FDCWD {
        tracing::trace!("readlinkat(path_name={})", path_buf.as_bstr());
        return Err(errno::EINVAL.into());
    }

    tracing::warn!("file descriptor relative `readlinkat` not supported");
    Err(errno::ENOSYS.into())
}

pub fn lseek<C: LinuxCpu>(ctx: &mut Ctx<C>, fd: u64, offset: u64, whence: u64) -> LinuxResult {
    let file = ctx.kernel.process.file_table.get(&mut ctx.kernel.process_manager, fd)?;
    let mut file = file.borrow_mut();
    let whence: Seek = whence.try_into()?;
    Ok(file.seek(offset as i64, whence)? as u64)
}

pub fn llseek<C: LinuxCpu>(
    ctx: &mut Ctx<C>,
    fd: u64,
    offset_hi: u64,
    offset_lo: u64,
    result: u64,
    whence: u64,
) -> LinuxResult {
    let offset = ((offset_hi & 0xffff_ffff) << 32) | (offset_lo & 0xffff_ffff);
    let new_offset = lseek(ctx, fd, offset, whence)?;
    ctx.write_user_struct(result, &types::libc::ulonglong::from(new_offset))?;
    Ok(0)
}

pub fn getcwd<C: LinuxCpu>(ctx: &mut Ctx<C>, buf: u64, size: u64) -> LinuxResult {
    if size < 2 {
        return Err(errno::ERANGE.into());
    }

    ctx.kernel.buffer.clear();

    ctx.kernel.vfs.path_to_root(&ctx.kernel.process.cwd().borrow(), &mut ctx.kernel.buffer);
    ctx.kernel.buffer.push(0);

    ctx.cpu.mem().write_bytes(buf, &ctx.kernel.buffer)?;
    Ok(buf)
}

pub fn chdir<C: LinuxCpu>(ctx: &mut Ctx<C>, path: u64) -> LinuxResult {
    ctx.kernel.buffer.clear();

    let path_buf: PathRef =
        ctx.kernel.arch.libc(path).read_cstr(ctx.cpu.mem(), &mut ctx.kernel.buffer)?;

    let dentry = ctx.kernel.vfs.resolve(ctx.kernel.process.cwd(), path_buf)?;
    if !dentry.borrow().is_dir() {
        return Err(errno::ENOTDIR.into());
    }

    ctx.kernel.process.working_dir = Some(dentry);

    Ok(0)
}

pub fn mkdir<C: LinuxCpu>(ctx: &mut Ctx<C>, pathname: u64, mode: u64) -> LinuxResult {
    ctx.kernel.buffer.clear();
    let path: PathRef =
        ctx.kernel.arch.libc(pathname).read_cstr(ctx.cpu.mem(), &mut ctx.kernel.buffer)?;
    ctx.kernel.vfs.create_dir(&ctx.kernel.process.cwd(), path, mode)?;
    Ok(0)
}

pub fn creat<C: LinuxCpu>(ctx: &mut Ctx<C>, pathname: u64, mode: u64) -> LinuxResult {
    ctx.kernel.buffer.clear();
    let path: PathRef =
        ctx.kernel.arch.libc(pathname).read_cstr(ctx.cpu.mem(), &mut ctx.kernel.buffer)?;
    ctx.kernel.vfs.create_file(&ctx.kernel.process.cwd(), path, mode)?;
    Ok(0)
}

pub fn readlink<C: LinuxCpu>(ctx: &mut Ctx<C>, path: u64, _buf: u64, _bufsiz: u64) -> LinuxResult {
    let path: PathRef =
        ctx.kernel.arch.libc(path).read_cstr(ctx.cpu.mem(), &mut ctx.kernel.buffer)?;
    tracing::debug!("readlink {:?}", path.as_bstr());
    Err(errno::EPERM.into())
}

pub fn chown<C: LinuxCpu>(ctx: &mut Ctx<C>, filename: u64, _user: u64, _group: u64) -> LinuxResult {
    let path: PathRef =
        ctx.kernel.arch.libc(filename).read_cstr(ctx.cpu.mem(), &mut ctx.kernel.buffer)?;
    tracing::debug!("chown {:?}", path.as_bstr());

    Ok(0)
}

pub fn getpid<C: LinuxCpu>(ctx: &mut Ctx<C>) -> LinuxResult {
    Ok(ctx.kernel.process.pid)
}

pub fn getgid<C: LinuxCpu>(ctx: &mut Ctx<C>) -> LinuxResult {
    Ok(ctx.kernel.process.uid)
}

pub fn getuid<C: LinuxCpu>(ctx: &mut Ctx<C>) -> LinuxResult {
    Ok(ctx.kernel.process.uid)
}

pub fn geteuid<C: LinuxCpu>(ctx: &mut Ctx<C>) -> LinuxResult {
    Ok(ctx.kernel.process.uid)
}

pub fn getegid<C: LinuxCpu>(ctx: &mut Ctx<C>) -> LinuxResult {
    Ok(ctx.kernel.process.uid)
}

pub fn setpgid<C: LinuxCpu>(_ctx: &mut Ctx<C>) -> LinuxResult {
    Ok(0)
}

pub fn getppid<C: LinuxCpu>(ctx: &mut Ctx<C>) -> LinuxResult {
    Ok(ctx.kernel.process.parent_pid)
}

pub fn getpgrp<C: LinuxCpu>(_ctx: &mut Ctx<C>) -> LinuxResult {
    Ok(0)
}

pub fn gettid<C: LinuxCpu>(ctx: &mut Ctx<C>) -> LinuxResult {
    Ok(ctx.kernel.process.pid)
}

pub fn setsid<C: LinuxCpu>(ctx: &mut Ctx<C>) -> LinuxResult {
    Ok(ctx.kernel.process.pid)
}

// @fixme: some of these constants are only correct for x64
pub fn fcntl<C: LinuxCpu>(ctx: &mut Ctx<C>, fd: u64, cmd: u64, arg: u64) -> LinuxResult {
    const F_DUPFD: u64 = 0;
    const F_GETFD: u64 = 1;
    const F_SETFD: u64 = 2;

    // Set record locking info
    const F_SETLKW: u64 = 7;

    let file = ctx.kernel.get_file(fd)?;
    match cmd {
        F_DUPFD => Ok(ctx.kernel.process.file_table.add(file)),
        F_GETFD => Ok(file.borrow_mut().flags),
        F_SETFD => {
            file.borrow_mut().flags = arg;
            Ok(arg)
        }
        F_SETLKW => {
            // We don't really support locks yet, but report success back to the program continues
            // to function
            Ok(0)
        }
        _ => Err(errno::EINVAL.into()),
    }
}

pub fn getdents<C: LinuxCpu>(ctx: &mut Ctx<C>, fd: u64, dirent: u64, count: u64) -> LinuxResult {
    getdents_inner(ctx, fd, dirent, count, false)
}

pub fn getdents64<C: LinuxCpu>(ctx: &mut Ctx<C>, fd: u64, dirent: u64, count: u64) -> LinuxResult {
    getdents_inner(ctx, fd, dirent, count, true)
}

pub fn getdents_inner<C: LinuxCpu>(
    ctx: &mut Ctx<C>,
    fd: u64,
    dirent: u64,
    count: u64,
    is64: bool,
) -> LinuxResult {
    let mut offset = 0;
    let mut bytes_written = 0;

    let mut writer = ctx.kernel.arch.libc(dirent);
    let size_of_long = writer.data_model.long_size().bytes() as u64;
    let size_of_short = writer.data_model.short_size().bytes() as u64;

    let file_ref = ctx.kernel.get_file(fd)?;
    let mut file = file_ref.borrow_mut();
    loop {
        let (name, child) = match file.iterate_dir() {
            Ok(entry) => entry,
            Err(errno::ENOENT) => break,
            Err(e) => return Err(e.into()),
        };
        offset += 1;

        let ino = child.borrow().index.ino as u64;

        if is64 {
            let unaligned_len = 2 * size_of_long + size_of_short + 1 + name.len() as u64 + 1;
            let len = align_up(unaligned_len, size_of_long);

            if len + bytes_written > count {
                break;
            }

            tracing::trace!("ino={}, off={}, reclen={}, name={}", ino, offset, len, name.as_bstr());
            writer.write::<arch::ULong, _>(ctx.cpu.mem(), ino)?;
            writer.write::<arch::ULong, _>(ctx.cpu.mem(), offset)?;
            writer.write::<arch::UShort, _>(ctx.cpu.mem(), len)?;
            writer.write_bytes(ctx.cpu.mem(), &[0])?;
            writer.write_bytes(ctx.cpu.mem(), &name)?;
            writer.write_bytes(ctx.cpu.mem(), &[0])?; // null terminator

            // Align next entry
            if unaligned_len < len {
                let bytes = &[0; 32][..(len - unaligned_len) as usize];
                writer.write_bytes(ctx.cpu.mem(), bytes)?;
            }
            bytes_written += len;
        }
        else {
            let unaligned_len = 2 * size_of_long + size_of_short + name.len() as u64 + 3;
            let len = align_up(unaligned_len, size_of_long);

            if len + bytes_written > count {
                break;
            }

            tracing::trace!("ino={}, off={}, reclen={}, name={}", ino, offset, len, name.as_bstr());
            writer.write::<arch::ULong, _>(ctx.cpu.mem(), ino)?;
            writer.write::<arch::ULong, _>(ctx.cpu.mem(), offset)?;
            writer.write::<arch::UShort, _>(ctx.cpu.mem(), len)?;
            writer.write_bytes(ctx.cpu.mem(), &name)?;
            writer.write_bytes(ctx.cpu.mem(), &[0])?; // null terminator
            writer.write_bytes(ctx.cpu.mem(), &[0, 0])?; // padding byte, and d_type

            // Align next entry
            if unaligned_len < len {
                let bytes = &[0; 32][..(len - unaligned_len) as usize];
                writer.write_bytes(ctx.cpu.mem(), bytes)?;
            }
            bytes_written += len;
        }
    }

    Ok(bytes_written)
}

pub fn brk<C: LinuxCpu>(ctx: &mut Ctx<C>, addr: u64) -> LinuxResult {
    let orig_brk = ctx.kernel.process.image.end_brk;

    if addr < ctx.kernel.process.image.start_brk {
        // Cannot shrink brk past the starting address so just return the original brk
        return Ok(orig_brk);
    }

    if addr - ctx.kernel.process.image.start_brk > ctx.kernel.max_alloc_size {
        // Allocation exceeds memory limit
        return Ok(orig_brk);
    }

    let is_shrinking = addr < orig_brk;
    if is_shrinking {
        ctx.cpu.mem().unmap(addr, orig_brk - addr);
    }
    else {
        let mapping =
            mem::Mapping { perm: perm::READ | perm::WRITE | perm::MAP | perm::INIT, value: 0x0 };
        if !ctx.cpu.mem().memmap(orig_brk, addr - orig_brk, mapping) {
            // Failed to allocate memory
            return Ok(orig_brk);
        }
    }

    ctx.kernel.process.image.end_brk = addr;
    ctx.kernel.process.mapping.get_mut(&ctx.kernel.process.image.start_brk).unwrap().end = addr;

    Ok(addr)
}

pub fn mmap<C: LinuxCpu>(
    ctx: &mut Ctx<C>,
    addr: u64,
    length: u64,
    prot: u64,
    flags: u64,
    fd: u64,
    offset: u64,
) -> LinuxResult {
    // @fixme[pagesize]: currently page size is constant.
    mmap2(ctx, addr, length, prot, flags, fd, offset / sys::PAGE_SIZE)
}

pub fn mmap_mips<C: LinuxCpu>(
    ctx: &mut Ctx<C>,
    addr: u64,
    length: u64,
    prot: u64,
    flags: u64,
    fd: u64,
    offset: u64,
) -> LinuxResult {
    mmap2_mips(ctx, addr, length, prot, flags, fd, offset / sys::PAGE_SIZE)
}

pub fn mmap2_mips<C: LinuxCpu>(
    ctx: &mut Ctx<C>,
    addr: u64,
    length: u64,
    prot: u64,
    mut flags: u64,
    fd: u64,
    pgoffset: u64,
) -> LinuxResult {
    use crate::sys::mmem;

    if flags & mmem::MAP_ANONYMOUS_MIPS != 0 {
        flags |= mmem::MAP_ANONYMOUS;
    }
    mmap2(ctx, addr, length, prot, flags, fd, pgoffset)
}

pub fn mmap2<C: LinuxCpu>(
    ctx: &mut Ctx<C>,
    addr: u64,
    length: u64,
    prot: u64,
    flags: u64,
    fd: u64,
    pgoffset: u64,
) -> LinuxResult {
    use crate::sys::mmem;
    ensure!(
        addr == align_down(addr, sys::PAGE_SIZE),
        "Unaligned address passed to mmap2: {:#0x}",
        addr
    );

    // @checkme: what is the correct behaviour is length is unaligned? Is an unaligned length valid
    // if we are mmaping a file?
    let alloc_len = align_up(length, sys::PAGE_SIZE);
    ensure!(addr.checked_add(alloc_len).is_some());

    match flags & 0x0F {
        mmem::MAP_SHARED => {
            // @fixme: Multiprocess support is still a work in progress.
            tracing::warn!("MAP_SHARED not fully supported");
        }
        mmem::MAP_PRIVATE => {}
        x => {
            tracing::warn!("Invalid mmap2 mapping type: {:0x}", x);
            return Err(errno::EINVAL.into());
        }
    }

    let is_file = flags & mmem::MAP_ANONYMOUS == 0;
    if is_file {
        // Before allocating memory, to load the file into, check whether file descriptor
        // corresponds to a valid file
        let _ = ctx.kernel.get_file(fd)?;
    }

    let is_fixed = flags & mmem::MAP_FIXED != 0;
    if is_fixed {
        // Remove any existing allocation the overlaps with this allocation
        if addr != NULL_PTR {
            let _ = ctx.kernel.free(ctx.cpu.mem(), addr, alloc_len);
        }
    }

    let addr = if addr == NULL_PTR { ctx.kernel.mmap_start_addr } else { addr };

    let alloc_addr = ctx.kernel.alloc(
        ctx.cpu.mem(),
        AllocLayout { addr: Some(addr), size: alloc_len, align: sys::PAGE_SIZE },
        sys::perm_from_prot(prot) | perm::MAP,
    )?;

    if is_fixed && alloc_addr != addr {
        tracing::error!("Wrong allocation address, wanted: {addr:#x} got: {alloc_addr:#x}");
        return Err(VmExit::OutOfMemory.into());
    }

    let written_bytes = if is_file {
        let file_ref = ctx.kernel.get_file(fd)?;
        let mut file = file_ref.borrow_mut();

        let end = alloc_addr + length;
        ctx.kernel
            .process
            .mapping
            .insert(alloc_addr, MemMappedFile { path: file.path.clone(), end });
        file.mmap(ctx.cpu.mem(), pgoffset * sys::PAGE_SIZE, alloc_addr, length)? as u64
    }
    else {
        if pgoffset != 0 {
            return Err(errno::EINVAL.into());
        }
        0
    };

    // Any extra data in the page is guaranteed to be zeroed on Linux.
    tracing::trace!(
        "zeroing {} additional bytes at: {:#x}",
        alloc_len - written_bytes,
        alloc_addr + written_bytes
    );
    ctx.cpu.mem().fill(alloc_addr + written_bytes, alloc_len - written_bytes, 0x00)?;

    Ok(alloc_addr)
}

pub fn mprotect<C: LinuxCpu>(ctx: &mut Ctx<C>, addr: u64, size: u64, prot: u64) -> LinuxResult {
    ctx.cpu.mem().update_perm(addr, size, sys::perm_from_prot(prot)).map_err(|_| errno::EACCES)?;
    Ok(0)
}

pub fn munmap<C: LinuxCpu>(ctx: &mut Ctx<C>, addr: u64, length: u64) -> LinuxResult {
    let end = align_up(addr.checked_add(length).ok_or(errno::EINVAL)?, sys::PAGE_SIZE);
    if end <= addr {
        return Err(errno::EINVAL.into());
    }
    ctx.kernel.free(ctx.cpu.mem(), addr, length)?;
    Ok(0)
}

// @fixme: used checked add for address calculations
pub fn mremap<C: LinuxCpu>(
    ctx: &mut Ctx<C>,
    old_addr: u64,
    old_size: u64,
    new_size: u64,
    flags: u64,
    _new_address: u64,
) -> LinuxResult {
    use crate::sys::mmem;

    // Check that the sizes of the memory regions are valid.
    if old_addr != align_down(old_addr, sys::PAGE_SIZE) || new_size == 0 || old_size == 0 {
        return Err(errno::EINVAL.into());
    }

    if flags & mmem::MREMAP_FIXED != 0 || flags & mmem::MREMAP_DONTUNMAP != 0 {
        tracing::warn!("Unsupported mremap flags: {:0b}", flags);
        return Err(errno::EINVAL.into());
    }

    let old_end = old_addr.checked_add(old_size).ok_or(errno::EINVAL)?;
    let new_end = old_addr.checked_add(new_size).ok_or(errno::EINVAL)?;

    // @fixme: properly check that this region is entirely mapped.
    let perm = ctx.cpu.mem().get_perm(old_addr) & ctx.cpu.mem().get_perm(old_end - 1);
    if perm == perm::NONE {
        // @fixme: deliver as SIGSEGV?
        return Err(VmExit::UnhandledException((ExceptionCode::ReadUnmapped, old_addr)).into());
    }

    if new_size < old_size {
        // Shrink memory map
        ctx.kernel.free(ctx.cpu.mem(), new_end, old_size - new_size)?;
        return Ok(old_addr);
    }

    // First try to allocate the memory directly after the current allocation.
    if flags & mmem::MREMAP_MAYMOVE == 0 || !ctx.kernel.force_mremap_move {
        let alloc_after =
            ctx.kernel.alloc_fixed(ctx.cpu.mem(), old_end, new_size - old_size, perm | perm::MAP);
        if alloc_after.is_ok() {
            return Ok(old_addr);
        }
    }

    // Failed to resize existing memory region, so return an error if the region is not movable.
    if flags & mmem::MREMAP_MAYMOVE == 0 {
        return Err(errno::ENOMEM.into());
    }

    // Find a free region of memory and copy the existing mapping into it
    let new_addr = ctx.kernel.find_free(ctx.cpu.mem(), new_size)?;
    if let Err(e) = ctx.cpu.mem().move_region(old_addr, old_size, new_addr) {
        // @fixme: deliver as SIGSEGV?
        return Err(
            VmExit::UnhandledException((ExceptionCode::from_load_error(e), old_addr)).into()
        );
    }

    // Map the rest of the region.
    ctx.kernel
        .alloc_fixed(ctx.cpu.mem(), new_addr + old_size, new_size - old_size, perm | perm::MAP)
        .unwrap();

    Ok(new_addr)
}

pub fn madvise<C: LinuxCpu>(
    _ctx: &mut Ctx<C>,
    _addr: u64,
    _length: u64,
    _advice: u64,
) -> LinuxResult {
    Ok(0)
}

pub fn stat_any<C: LinuxCpu>(
    ctx: &mut Ctx<C>,
    path: u64,
    buf: u64,
    is_stat64: bool,
) -> LinuxResult {
    let path_buf: &[u8] =
        ctx.kernel.arch.libc(path).read_cstr(ctx.cpu.mem(), &mut ctx.kernel.buffer)?;

    let dir = ctx.kernel.vfs.resolve(ctx.kernel.process.cwd(), path_buf)?;
    let stat = {
        let dir = dir.borrow();
        fs::with_inode_mut(&dir.inode, |inode| (inode.vtable.stat)(inode))?
    };

    ctx.kernel.buffer.clear();
    match is_stat64 {
        true => stat.encode_stat64(ctx.kernel.arch.triple.architecture, &mut ctx.kernel.buffer),
        false => stat.encode_stat(ctx.kernel.arch.triple.architecture, &mut ctx.kernel.buffer),
    }

    ctx.cpu.mem().write_bytes(buf, &ctx.kernel.buffer)?;
    Ok(0)
}

pub fn stat<C: LinuxCpu>(ctx: &mut Ctx<C>, path: u64, buf: u64) -> LinuxResult {
    stat_any(ctx, path, buf, false)
}

pub fn stat64<C: LinuxCpu>(ctx: &mut Ctx<C>, path: u64, buf: u64) -> LinuxResult {
    stat_any(ctx, path, buf, true)
}

pub fn fstat_any<C: LinuxCpu>(ctx: &mut Ctx<C>, fd: u64, buf: u64, is_stat64: bool) -> LinuxResult {
    let file = ctx.kernel.get_file(fd)?;
    let stat = {
        let file = file.borrow();
        let mut inode = file.inode.borrow_mut();
        (inode.vtable.stat)(&mut inode)?
    };
    ctx.kernel.buffer.clear();
    match is_stat64 {
        true => stat.encode_stat64(ctx.kernel.arch.triple.architecture, &mut ctx.kernel.buffer),
        false => stat.encode_stat(ctx.kernel.arch.triple.architecture, &mut ctx.kernel.buffer),
    }

    ctx.cpu.mem().write_bytes(buf, &ctx.kernel.buffer)?;

    Ok(0)
}

pub fn fstat<C: LinuxCpu>(ctx: &mut Ctx<C>, fd: u64, buf: u64) -> LinuxResult {
    fstat_any(ctx, fd, buf, false)
}

pub fn fstat64<C: LinuxCpu>(ctx: &mut Ctx<C>, fd: u64, buf: u64) -> LinuxResult {
    fstat_any(ctx, fd, buf, true)
}

pub fn fstatat64<C: LinuxCpu>(
    ctx: &mut Ctx<C>,
    dirfd: u64,
    pathname: u64,
    buf: u64,
) -> LinuxResult {
    const AT_FDCWD: i32 = -100_i32;

    if dirfd as u32 as i32 == AT_FDCWD {
        return stat64(ctx, pathname, buf);
    }

    tracing::warn!("file descriptor relative `fstatat` not supported");
    Err(errno::ENOSYS.into())
}

pub fn lstat<C: LinuxCpu>(ctx: &mut Ctx<C>, path: u64, buf: u64) -> LinuxResult {
    // FIXME: handle symbolic links
    stat(ctx, path, buf)
}

pub fn lstat64<C: LinuxCpu>(ctx: &mut Ctx<C>, path: u64, buf: u64) -> LinuxResult {
    // FIXME: handle symbolic links
    stat64(ctx, path, buf)
}

pub fn olduname<C: LinuxCpu>(ctx: &mut Ctx<C>, buf: u64) -> LinuxResult {
    const UTSNAME_LENGTH: u64 = 9;

    let uname_values: &[&[u8]] = &[
        b"Linux\0",                     // sysname
        b"node-01\0",                   // nodename
        b"4.4.0-999\0",                 // release
        b"#01\0",                       // version
        &ctx.kernel.arch.platform_name, // machine
    ];
    let mem = ctx.cpu.mem();
    for (i, value) in uname_values.iter().enumerate() {
        mem.write_bytes(buf + i as u64 * UTSNAME_LENGTH, value)?;
    }

    Ok(0)
}

pub fn uname<C: LinuxCpu>(ctx: &mut Ctx<C>, buf: u64) -> LinuxResult {
    write_uname(ctx, buf, false)
}

pub fn newuname<C: LinuxCpu>(ctx: &mut Ctx<C>, buf: u64) -> LinuxResult {
    write_uname(ctx, buf, true)
}

pub fn write_uname<C: LinuxCpu>(ctx: &mut Ctx<C>, buf: u64, new: bool) -> LinuxResult {
    const UTSNAME_LENGTH: u64 = 65;

    let uname_values: &[&[u8]] = &[
        b"Linux\0",                     // sysname
        b"IcicleVM-0001\0",             // nodename
        b"5.4.0-74-icicle\0",           // release
        b"#01-Icicle\0",                // version
        &ctx.kernel.arch.platform_name, // machine
    ];
    let mem = ctx.cpu.mem();
    for (i, value) in uname_values.iter().enumerate() {
        mem.write_bytes(buf + i as u64 * UTSNAME_LENGTH, value)?;
    }

    if new {
        // domain name
        mem.write_bytes(
            buf + uname_values.len() as u64 * UTSNAME_LENGTH,
            b"icicle.network.internal\0",
        )?;
    }

    Ok(0)
}

pub fn sethostname<C: LinuxCpu>(ctx: &mut Ctx<C>, hostname: u64, len: u64) -> LinuxResult {
    if len > 64 {
        return Err(errno::EINVAL.into());
    }
    ctx.kernel.buffer.clear();
    read_user(ctx.cpu.mem(), hostname, len as usize, &mut ctx.kernel.buffer)?;

    ctx.kernel.hostname.clear();
    ctx.kernel.hostname.extend_from_slice(&ctx.kernel.buffer);
    tracing::info!("Hostname set to: {}", ctx.kernel.hostname.as_bstr());

    Ok(0)
}

pub fn sysinfo<C: LinuxCpu>(ctx: &mut Ctx<C>, info: u64) -> LinuxResult {
    let mut writer = ctx.kernel.arch.libc(info);

    let mem = ctx.cpu.mem();
    writer.write::<arch::ULong, _>(mem, 0)?; // Seconds since boot

    writer.write::<arch::ULong, _>(mem, 0)?; // 1 minute load averages
    writer.write::<arch::ULong, _>(mem, 0)?; // 5 minute load averages
    writer.write::<arch::ULong, _>(mem, 0)?; // 15 minute load averages

    writer.write::<arch::ULong, _>(mem, 0)?; // Total usable main memory size
    writer.write::<arch::ULong, _>(mem, 0)?; // Available memory size
    writer.write::<arch::ULong, _>(mem, 0)?; // Amount of shared memory
    writer.write::<arch::ULong, _>(mem, 0)?; // Memory used by buffers
    writer.write::<arch::ULong, _>(mem, 0)?; // Total swap space size
    writer.write::<arch::ULong, _>(mem, 0)?; // Swap space still available
    writer.write::<arch::UShort, _>(mem, 1)?; // Number of current processes
    writer.write::<arch::ULong, _>(mem, 0)?; // Total high memory size
    writer.write::<arch::ULong, _>(mem, 0)?; // Available high memory size
    writer.write::<arch::UInt, _>(mem, 1)?; // Memory unit size in bytes

    Ok(0)
}

pub fn prctl<C: LinuxCpu>(
    ctx: &mut Ctx<C>,
    option: u64,
    arg2: u64,
    _arg3: u64,
    _arg4: u64,
    _arg5: u64,
) -> LinuxResult {
    match option {
        sys::prctl::PR_GET_NAME => {
            ctx.cpu.mem().write_bytes(arg2, &ctx.kernel.process.name)?;
            Ok(0)
        }
        sys::prctl::PR_SET_NAME => {
            ctx.cpu.mem().read_bytes(arg2, &mut ctx.kernel.process.name)?;
            ctx.kernel.process.name[15] = 0;
            tracing::info!(
                "pid({}) = {}",
                ctx.kernel.process.pid,
                ctx.kernel.process.name.as_bstr()
            );
            Ok(0)
        }
        _ => Err(errno::EINVAL.into()),
    }
}

pub fn prctl_mips<C: LinuxCpu>(
    _ctx: &mut Ctx<C>,
    option: u64,
    _arg2: u64,
    _arg3: u64,
    _arg4: u64,
    _arg5: u64,
) -> LinuxResult {
    match option {
        sys::PR_GET_FP_MODE => Ok(0),
        sys::PR_SET_FP_MODE => Ok(0),
        _ => Err(errno::EINVAL.into()),
    }
}

pub mod x86 {
    pub mod arch {
        pub const SET_GS: u32 = 0x1001;
        pub const SET_FS: u32 = 0x1002;
        pub const GET_FS: u32 = 0x1003;
        pub const GET_GS: u32 = 0x1004;

        pub const GET_CPUID: u32 = 0x1011;
        pub const SET_CPUID: u32 = 0x1012;

        pub const MAP_VDSO_X32: u32 = 0x2001;
        pub const MAP_VDSO_32: u32 = 0x2002;
        pub const MAP_VDSO_64: u32 = 0x2003;

        pub const ARCH_CET_STATUS: u32 = 0x3001;
        pub const ARCH_CET_DISABLE: u32 = 0x3002;
        pub const ARCH_CET_LOCK: u32 = 0x3003;
        pub const ARCH_CET_EXEC: u32 = 0x3004;
        pub const ARCH_CET_ALLOC_SHSTK: u32 = 0x3005;
        pub const ARCH_CET_PUSH_SHSTK: u32 = 0x3006;
    }
}

pub fn arch_prctl<C: LinuxCpu>(_ctx: &mut Ctx<C>, code: u64, addr: u64) -> LinuxResult {
    tracing::warn!("Unknown `arch_prctl` code: {:0x}, addr = {:0x}", code, addr);
    Err(errno::EINVAL.into())
}

pub fn arch_prctl_x64<C: LinuxCpu>(ctx: &mut Ctx<C>, code: u64, addr: u64) -> LinuxResult {
    match code as u32 {
        x86::arch::ARCH_CET_STATUS => {
            tracing::warn!("ARCH_CET_STATUS not supported");
            Err(errno::EINVAL.into())
        }
        x86::arch::SET_FS => {
            let fs_offset = ctx.cpu.sleigh().get_reg("FS_OFFSET").unwrap().var;
            ctx.cpu.write_var(fs_offset, addr);
            Ok(0)
        }
        x86::arch::SET_GS => {
            let gs_offset = ctx.cpu.sleigh().get_reg("GS_OFFSET").unwrap().var;
            ctx.cpu.write_var(gs_offset, addr);
            Ok(0)
        }
        _ => {
            tracing::warn!("Unknown `arch_prctl` code: {:0x}, addr = {:0x}", code, addr);
            Err(errno::EINVAL.into())
        }
    }
}

pub fn ioctl<C: LinuxCpu>(ctx: &mut Ctx<C>, fd: u64, request: u64) -> LinuxResult {
    let _file = ctx.kernel.get_file(fd)?;

    match request {
        // Get current serial port settings
        0x5401 => Err(errno::ENOTTY.into()),

        // TIOCGWINSZ
        0x5413 => Err(errno::ENOTTY.into()),

        // TIOCGPGRP
        0x540f => Err(errno::ENOSYS.into()),

        // TIOCSPGRP
        0x5410 => Err(errno::ENOSYS.into()),

        _ => Err(errno::ENOTTY.into()),
    }
}

pub fn exit<C: LinuxCpu>(ctx: &mut Ctx<C>, status: u64) -> LinuxResult {
    exit_group(ctx, status)
}

pub fn exit_group<C: LinuxCpu>(ctx: &mut Ctx<C>, status: u64) -> LinuxResult {
    match ctx.kernel.destroy_process(ctx.cpu, TerminationReason::Exit(status)) {
        Some(err) => Err(err.into()),
        None => Ok(0),
    }
}

pub fn wait4<C: LinuxCpu>(
    ctx: &mut Ctx<C>,
    pid: u64,
    wstatus: u64,
    _options: u64,
    _rusage: u64,
) -> LinuxResult {
    let (event_pid, termination) = match ctx.kernel.process.process_events.drain(..).last() {
        // @fixme: check `pid` matches `event_pid`.
        Some(entry) => entry,
        None => {
            match pid as i32 {
                // Wait for any child process.
                -1 => {
                    let mut found_process = false;
                    for parked in ctx.kernel.process_manager.parked.iter_mut() {
                        // @fixme: should check for ancestors.
                        if parked.process.parent_pid == ctx.kernel.process.pid {
                            parked.process.listeners.insert(ctx.kernel.process.pid);
                            found_process = true;
                        }
                    }

                    if !found_process {
                        return Err(errno::ECHILD.into());
                    }
                }

                // Wait for any child within process group given by the absolute value of the pid.
                // @fixme: handle this case
                x if x < 0 => return Err(errno::ENOSYS.into()),

                // Wait for a specific PID.
                _ => {
                    let parked = ctx.kernel.process_manager.get_mut(pid).ok_or(errno::ECHILD)?;
                    parked.process.listeners.insert(ctx.kernel.process.pid);
                }
            }
            // @fixme: check `WNOHANG` flag
            return ctx.kernel.switch_task(ctx.cpu, crate::PauseReason::WaitProcess);
        }
    };

    if wstatus != NULL_PTR {
        let status = match termination {
            TerminationReason::Exit(status) => status,
            TerminationReason::Killed(signal) => (signal & 0xff) | (0x7f << 8),
        };
        ctx.kernel.arch.libc(wstatus).write::<arch::UInt, _>(ctx.cpu.mem(), status)?;
    }

    Ok(event_pid)
}

pub fn kill<C: LinuxCpu>(ctx: &mut Ctx<C>, pid: u64, sig: u64) -> LinuxResult {
    tracing::debug!("pid={}, sig={}", pid, sig);

    if (pid as i64) < 0 {
        tracing::warn!("Unsupported kill command pid={}, sig={}", pid, sig);
        return Err(errno::ENOSYS.into());
    }

    if sig >= 64 {
        return Err(errno::EINVAL.into());
    }

    let sigbit = if sig == 0 { 0 } else { 1 << (sig - 1) };

    let mut signal_delivered = false;
    if pid == 0 {
        // Send signal to any processes in the same group and to self.
        for parked in ctx.kernel.process_manager.parked.iter_mut() {
            parked.process.pending_signals |= sigbit;
        }

        ctx.kernel.process.pending_signals |= sigbit;
        signal_delivered = true;
    }
    else if pid == ctx.kernel.process.pid {
        // Send a signal to self.
        ctx.kernel.process.pending_signals |= sigbit;
        signal_delivered = true;
    }
    else {
        // Send a signal to a specific target process.
        if let Some(parked) = ctx.kernel.process_manager.get_mut(pid) {
            parked.process.pending_signals |= sigbit;
            signal_delivered = true;
        }
    }

    match signal_delivered {
        true => Ok(0),
        false => Err(errno::ESRCH.into()),
    }
}

pub fn tkill<C: LinuxCpu>(ctx: &mut Ctx<C>, tid: u64, sig: u64) -> LinuxResult {
    let tgid = ctx.kernel.process.pid;
    tgkill(ctx, tgid, tid, sig)
}

pub fn tgkill<C: LinuxCpu>(ctx: &mut Ctx<C>, tgid: u64, tid: u64, sig: u64) -> LinuxResult {
    tracing::debug!("tgid={}, tid={}, sig={}", tgid, tid, sig);

    // We only support a single thread/thread group and that thread group must be the main thread
    if tgid != ctx.kernel.process.pid && (tid != 0 || tid != ctx.kernel.process.pid) {
        return Err(errno::EINVAL.into());
    }

    kill(ctx, tid, sig)
}

pub fn set_tid_address<C: LinuxCpu>(_ctx: &mut Ctx<C>, _tidptr: u64) -> LinuxResult {
    // @fixme: revisit this when we get proper multithreading support
    Ok(0x1234)
}

pub fn set_thread_area_mips<C: LinuxCpu>(ctx: &mut Ctx<C>, addr: u64) -> LinuxResult {
    let user_local = ctx.cpu.sleigh().get_reg("HW_ULR").unwrap().var;
    ctx.cpu.write_var(user_local, addr);
    Ok(0)
}

pub fn set_thread_area_x86<C: LinuxCpu>(ctx: &mut Ctx<C>, user_desc: u64) -> LinuxResult {
    tracing::warn!("set_thread_area might not be implemented correctly");
    let buf = read_user(ctx.cpu.mem(), user_desc, 16, &mut ctx.kernel.buffer)?;

    let entry_number = i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if entry_number != -1 {
        tracing::warn!("update to existing thread area not supported");
        return Err(errno::ENOSYS.into());
    }

    let entry = arch::x86::GDTEntry {
        base: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
        limit: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
        // @fixme: set flags and access bits
        flags: 0,
        access: 0,
    };

    // Write the entry to the GDT at position 12 (an arbitary position to use for now)
    let gdb_descriptor: u32 = 12;
    let gdtr = ctx.cpu.sleigh().get_reg("GDTR").unwrap().var;
    let gdt_addr: u64 = ctx.cpu.read_var(gdtr);
    ctx.cpu.mem().write_bytes(gdt_addr + gdb_descriptor as u64 * 8, &entry.to_bytes())?;

    // Update the `user_desc` struct in user space
    ctx.kernel.arch.libc(user_desc).write::<arch::U32, _>(ctx.cpu.mem(), gdb_descriptor as u64)?;

    Ok(0)
}

#[allow(unused)]
pub mod clone {
    bitflags::bitflags! {
        #[derive(Debug, Default)]
        pub struct Flags: u64 {
            const VM = 0x00000100;
            const FS = 0x00000200;
            const FILES = 0x00000400;
            const SIGHAND = 0x00000800;
            const PIDFD = 0x00001000;
            const PTRACE = 0x00002000;
            const VFORK = 0x00004000;
            const PARENT = 0x00008000;
            const THREAD = 0x00010000;
            const NEWNS = 0x00020000;
            const SYSVSEM = 0x00040000;
            const SETTLS = 0x00080000;
            const PARENT_SETTID = 0x00100000;
            const CHILD_CLEARTID = 0x00200000;
            const DETACHED = 0x00400000;
            const UNTRACED = 0x00800000;
            const CHILD_SETTID = 0x01000000;
            const NEWCGROUP = 0x02000000;
            const NEWUTS = 0x04000000;
            const NEWIPC = 0x08000000;
            const NEWUSER = 0x10000000;
            const NEWPID = 0x20000000;
            const NEWNET = 0x40000000;
            const IO = 0x80000000;
        }
    }
}

pub fn execve<C: LinuxCpu>(ctx: &mut Ctx<C>, pathname: u64, argv: u64, envp: u64) -> LinuxResult {
    let mut buf = vec![0; 1024];

    // Read argv from user-space
    let mut args = vec![];
    let mut arg_reader = ctx.kernel.arch.libc(argv);
    loop {
        let ptr = arg_reader.read::<arch::Ptr, _>(ctx.cpu.mem())?;
        if ptr == NULL_PTR {
            break;
        }
        let mut arg = ctx.kernel.arch.libc(ptr).read_cstr(ctx.cpu.mem(), &mut buf)?.to_vec();
        arg.push(0);
        args.push(arg);
    }

    // Read envp from user-space
    let mut env = vec![];
    let mut env_reader = ctx.kernel.arch.libc(envp);
    loop {
        let ptr = env_reader.read::<arch::Ptr, _>(ctx.cpu.mem())?;
        if ptr == NULL_PTR {
            break;
        }
        let mut env_val = ctx.kernel.arch.libc(ptr).read_cstr(ctx.cpu.mem(), &mut buf)?.to_vec();
        env.push(ctx.kernel.arch.libc(ptr).read_cstr(ctx.cpu.mem(), &mut env_val)?.to_vec());
    }

    ctx.kernel.set_env(&args, &env);

    let path = ctx.kernel.arch.libc(pathname).read_cstr(ctx.cpu.mem(), &mut buf)?;

    // @todo: remove when we have better tools for debugging.
    eprint!("[pid={}] exec: {} ", ctx.kernel.process.pid, path.as_bstr());
    for arg in &args {
        eprint!("{} ", arg[..arg.len() - 1].as_bstr());
    }
    eprintln!();

    // match ctx.kernel.load(ctx.cpu, path) {
    //     Ok(_) => {
    //         ctx.cpu.set_next_pc(ctx.cpu.read_pc());
    //         Ok(0)
    //     }
    //     Err(e) => {
    //         tracing::warn!("execve failed: {}", e);
    //         Err(errno::ENOENT.into())
    //     }
    // }

    Err(errno::ENOENT.into())
}

pub fn fork<C: LinuxCpu>(ctx: &mut Ctx<C>) -> LinuxResult {
    // The forked process will resume after the syscall.
    ctx.kernel.clone_state = CloneState::default();
    ctx.kernel.fork(ctx.cpu)
}

pub fn clone_x86<C: LinuxCpu>(
    ctx: &mut Ctx<C>,
    clone_flags: u64,
    new_sp: u64,
    parent_tidptr: u64,
    child_tidptr: u64,
    tls_ptr: u64,
) -> LinuxResult {
    let flags = clone::Flags::from_bits(clone_flags & !0xff).ok_or(errno::EINVAL)?;
    ctx.kernel.clone_state = CloneState { flags, new_sp, parent_tidptr, child_tidptr, tls_ptr };
    tracing::debug!("clone({:0x?})", ctx.kernel.clone_state);
    ctx.kernel.fork(ctx.cpu)
}

pub fn clone_mips<C: LinuxCpu>(
    ctx: &mut Ctx<C>,
    clone_flags: u64,
    new_sp: u64,
    parent_tidptr: u64,
    tls_ptr: u64,
    child_tidptr: u64,
) -> LinuxResult {
    let flags = clone::Flags::from_bits(clone_flags & !0xff).ok_or(errno::EINVAL)?;
    ctx.kernel.clone_state = CloneState { flags, new_sp, parent_tidptr, child_tidptr, tls_ptr };
    tracing::debug!("clone({:0x?})", ctx.kernel.clone_state);
    ctx.kernel.fork(ctx.cpu)
}

#[allow(unused)]
mod futex {
    pub const WAIT: u64 = 0;
    pub const WAKE: u64 = 1;
    pub const FD: u64 = 2;
    pub const REQUEUE: u64 = 3;
    pub const CMP_REQUEUE: u64 = 4;
    pub const WAKE_OP: u64 = 5;
    pub const LOCK_PI: u64 = 6;
    pub const UNLOCK_PI: u64 = 7;
    pub const TRYLOCK_PI: u64 = 8;
    pub const WAIT_BITSET: u64 = 9;
    pub const WAKE_BITSET: u64 = 10;
    pub const WAIT_REQUEUE_PI: u64 = 11;
    pub const CMP_REQUEUE_PI: u64 = 12;
    pub const PRIVATE_FLAG: u64 = 128;
    pub const CLOCK_REALTIME: u64 = 256;
    pub const CMD_MASK: u64 = !(PRIVATE_FLAG | CLOCK_REALTIME);
}

pub fn futex<C: LinuxCpu>(
    ctx: &mut Ctx<C>,
    uaddr: u64,
    op: u64,
    val: u64,
    _timeout: u64,
    _uaddr2: u64,
    _val3: u64,
) -> LinuxResult {
    match op & futex::CMD_MASK {
        futex::WAIT => {
            if ctx.kernel.arch.libc(uaddr).read::<arch::Ptr, _>(ctx.cpu.mem())? != val {
                return Err(errno::EAGAIN.into());
            }
            Ok(0)
        }
        _ => Err(errno::ENOSYS.into()),
    }
}

#[allow(unused)]
mod ipc {
    pub const SEMOP: u16 = 1;
    pub const SEMGET: u16 = 2;
    pub const SEMCTL: u16 = 3;
    pub const SEMTIMEDOP: u16 = 4;
    pub const MSGSND: u16 = 11;
    pub const MSGRCV: u16 = 12;
    pub const MSGGET: u16 = 13;
    pub const MSGCTL: u16 = 14;
    pub const SHMAT: u16 = 21;
    pub const SHMDT: u16 = 22;
    pub const SHMGET: u16 = 23;
    pub const SHMCTL: u16 = 24;

    pub const IPC_PRIVATE: u64 = 0;

    /// Specifies that a new key should be created if one doesn't already exist.
    pub const IPC_CREAT: u64 = 0o0001000;
    /// Return `EEXIST` if the key exists in the current namespace.
    pub const IPC_EXCL: u64 = 0o0002000;
    /// Return `EAGAIN` if the process would need to wait.
    pub const IPC_NOWAIT: u64 = 0o0004000;

    /// Remove the resource.
    pub const IPC_RMID: u64 = 0;
    /// Update kernel data structure for the IPC resource.
    pub const IPC_SET: u64 = 1;
    /// Copy the kernel data structure for the IPC resource to userspace
    pub const IPC_STAT: u64 = 2;
    /// Return info on system-wide IPC limits.
    pub const IPC_INFO: u64 = 3;

    pub const IPC_64_FLAG: u64 = 0x100;

    pub fn parse_ctl_version(cmd: u64) -> (u64, bool) {
        let version = cmd & IPC_64_FLAG != 0;
        (cmd & (!IPC_64_FLAG), version)
    }

    pub mod sem {
        pub const GETPID: u64 = 11;
        pub const GETVAL: u64 = 12;
        pub const GETALL: u64 = 13;
        pub const GETNCNT: u64 = 14;
        pub const GETZCNT: u64 = 15;
        pub const SETVAL: u64 = 16;
        pub const SETALL: u64 = 17;
        pub const INFO: u64 = 19;

        pub const UNDO: u64 = 0x1000;

        // @todo: allow the constants below to be configured

        /// The maximum number of semaphore sets allowed by the system.
        pub const SEMMNI: usize = 128;

        /// The maximum number of semaphores allowed in each semaphore set.
        pub const SEMMSL: usize = 250;

        /// Maximum number value for semval
        pub const SEMVMX: u64 = 0x7fff;
    }

    pub mod shmem {
        pub const LOCK: u64 = 11;
        pub const UNLOCK: u64 = 12;
        pub const STAT: u64 = 13;
        pub const INFO: u64 = 14;
        pub const STAT_ANY: u64 = 15;
    }
}

pub fn ipc<C: LinuxCpu>(
    ctx: &mut Ctx<C>,
    call: u64,
    first: u64,
    second: u64,
    third: u64,
    ptr: u64,
    _fifth: u64,
) -> LinuxResult {
    fn ipc_unimplemented(name: &str) -> LinuxResult {
        tracing::warn!("{} unimplemented", name);
        Err(errno::ENOSYS.into())
    }

    let version = call >> 16;
    let call = call as u16;

    match call {
        ipc::SEMOP => semop(ctx, first, ptr, second),
        ipc::SEMGET => semget(ctx, first, second, third),
        ipc::SEMCTL => {
            if ptr == NULL_PTR {
                return Err(errno::EINVAL.into());
            }
            let arg = ctx.read_user_struct::<types::libc::ulong>(ptr)?.value;
            semctl_old(ctx, first, second, third, arg)
        }
        ipc::SEMTIMEDOP => ipc_unimplemented("SEMTIMEDOP"),
        ipc::MSGSND => ipc_unimplemented("MSGSND"),
        ipc::MSGRCV => ipc_unimplemented("MSGRCV"),
        ipc::MSGGET => ipc_unimplemented("MSGGET"),
        ipc::MSGCTL => ipc_unimplemented("MSGCTL"),
        ipc::SHMAT => {
            if version == 1 {
                return Err(errno::EINVAL.into());
            }
            let raddr = do_shmat(ctx, first, ptr, second)?;
            ctx.write_user_struct(raddr, &types::libc::intptr_t::from(ptr))?;
            Ok(0)
        }
        ipc::SHMDT => shmdt(ctx, ptr),
        ipc::SHMGET => shmget(ctx, first, second, third),
        ipc::SHMCTL => shmctl(ctx, first, second, ptr),

        _ => Err(errno::ENOSYS.into()),
    }
}

fn semop<C: LinuxCpu>(ctx: &mut Ctx<C>, semid: u64, sops: u64, nsops: u64) -> LinuxResult {
    tracing::debug!("semop({}, {:#0x}, {})", semid, sops, nsops);

    if nsops < 1 {
        return Err(errno::EINVAL.into());
    }
    let set = ctx.kernel.ipc.semaphore_sets.get_mut(&semid).ok_or(errno::EINVAL)?;

    let mut reader = ctx.kernel.arch.libc(sops);
    let entries: Vec<SemBuf> =
        (0..nsops).map(|_| reader.read_struct(ctx.cpu.mem())).collect::<Result<_, _>>()?;

    // @fixme: all operations should happen atomically (i.e. either they all are executed or none of
    // them are). Probably will need multiple passes over the array.
    for entry in entries {
        let sem_index = entry.sem_num.value as usize;
        let n_semaphores = set.semaphores.len();

        let no_wait = entry.sem_flg.value & ipc::IPC_NOWAIT != 0;
        let undo = entry.sem_flg.value & ipc::sem::UNDO != 0;

        let semaphore = set.semaphores.get_mut(sem_index).ok_or(errno::EFBIG)?;
        let value = entry.sem_op.value;

        let result =
            match (semaphore.semval as i64).checked_add(value as i64).ok_or(errno::ERANGE)? {
                x if x > ipc::sem::SEMVMX as i64 => return Err(errno::ERANGE.into()),
                x if x < 0 => {
                    if no_wait {
                        return Err(errno::EAGAIN.into());
                    }
                    return ctx.kernel.switch_task(ctx.cpu, crate::PauseReason::WaitFile);
                }
                x => x,
            };

        if undo {
            let undo_entry = ctx
                .kernel
                .process
                .ipc
                .semaphore_undo
                .entry(semid)
                .or_insert_with(|| SemaphoreSetUndo::new(n_semaphores));
            undo_entry.semadj[sem_index] -= value as i64;
        }
        semaphore.semval = result as u64;
    }

    Ok(0)
}

fn semctl_old<C: LinuxCpu>(
    ctx: &mut Ctx<C>,
    semid: u64,
    semnum: u64,
    cmd: u64,
    arg: u64,
) -> LinuxResult {
    macro_rules! semctl_unimplemented {
        ($name:expr) => {{
            tracing::warn!("semctl({}, {}, {}, {:#0x}) unimplemented", semid, $name, semnum, arg);
            Err(errno::ENOSYS.into())
        }};
    }

    let (cmd, _is_ipc_64) = ipc::parse_ctl_version(cmd);
    match cmd {
        ipc::IPC_RMID => {
            // @fixme: handle wakeup of any waiting tasks.
            ctx.kernel.ipc.destroy_semset(semid)?;
            Ok(0)
        }
        ipc::IPC_SET => semctl_unimplemented!("IPC_SET"),
        ipc::IPC_STAT => semctl_unimplemented!("IPC_STAT"),
        ipc::IPC_INFO => semctl_unimplemented!("IPC_INFO"),
        ipc::sem::INFO => semctl_unimplemented!("SEM_INFO"),
        ipc::sem::GETPID => semctl_unimplemented!("GETPID"),
        ipc::sem::GETVAL => semctl_getval(ctx.kernel, semid, semnum),
        ipc::sem::GETALL => semctl_unimplemented!("GETALL"),
        ipc::sem::GETNCNT => semctl_unimplemented!("GETNCNT"),
        ipc::sem::GETZCNT => semctl_unimplemented!("GETZCNT"),
        ipc::sem::SETVAL => semctl_setval(ctx.kernel, semid, semnum, arg),
        ipc::sem::SETALL => semctl_unimplemented!("SETALL"),
        _ => Err(errno::EINVAL.into()),
    }
}

fn semctl_setval(kernel: &mut Kernel, semid: u64, semnum: u64, val: u64) -> LinuxResult {
    tracing::debug!("semctl_setval({}, {}, {})", semid, semnum, val);

    let set = kernel.ipc.semaphore_sets.get_mut(&semid).ok_or(errno::EINVAL)?;
    let semaphore = set.semaphores.get_mut(semnum as usize).ok_or(errno::EINVAL)?;
    semaphore.semval = val;
    Ok(0)
}

fn semctl_getval(kernel: &mut Kernel, semid: u64, semnum: u64) -> LinuxResult {
    let set = kernel.ipc.semaphore_sets.get_mut(&semid).ok_or(errno::EINVAL)?;
    let semaphore = set.semaphores.get_mut(semnum as usize).ok_or(errno::EINVAL)?;
    tracing::debug!("semctl_getval({}, {}) = {}", semid, semnum, semaphore.semval);
    Ok(semaphore.semval)
}

// @todo: handle/check permissions
// @todo: set creation time
fn semget<C: LinuxCpu>(ctx: &mut Ctx<C>, key: u64, nsems: u64, semflg: u64) -> LinuxResult {
    tracing::debug!("semget({}, {}, {:#0x})", key, nsems, semflg);

    if nsems as usize > ipc::sem::SEMMSL {
        tracing::debug!("Too many semaphores for set: {} (max: {})", nsems, ipc::sem::SEMMSL);
        return Err(errno::EINVAL.into());
    }

    let _semaphore_set = {
        if key == ipc::IPC_PRIVATE {
            tracing::warn!("IPC_PRIVATE not supported");
            return Err(errno::ENOSYS.into());
        }
        match ctx.kernel.ipc.semaphore_sets.get_mut(&key) {
            None => {
                if semflg & ipc::IPC_CREAT == 0 {
                    return Err(errno::ENOENT.into());
                }
                if ctx.kernel.ipc.semaphore_sets.len() >= ipc::sem::SEMMNI {
                    return Err(errno::ENOSPC.into());
                }
                if nsems == 0 {
                    return Err(errno::EINVAL.into());
                }

                let mut set = SemaphoreSet::new(nsems as usize);
                set.perm = ctx.kernel.init_ipc_perm(key, semflg);

                ctx.kernel.ipc.semaphore_sets.entry(key).or_insert(set)
            }
            Some(entry) => {
                if semflg & ipc::IPC_CREAT != 0 && semflg & ipc::IPC_EXCL != 0 {
                    return Err(errno::EEXIST.into());
                }
                entry
            }
        }
    };

    Ok(key)
}

fn do_shmat<C: LinuxCpu>(ctx: &mut Ctx<C>, shmid: u64, shmaddr: u64, shmflg: u64) -> LinuxResult {
    tracing::debug!("shmat({}, {:#0x}, {:#0x})", shmid, shmaddr, shmflg);

    let shmem = ctx.kernel.ipc.shmem.get_mut(&shmid).ok_or_else(|| {
        tracing::debug!("shmid: {} not found", shmid);
        errno::EINVAL
    })?;

    // @todo check SHM_REMAP flag.
    let addr = ctx.cpu.mem().next_free(AllocLayout {
        addr: (shmaddr != 0).then_some(shmaddr),
        size: shmem.physical_pages.len() as u64 * sys::PAGE_SIZE,
        align: sys::PAGE_SIZE,
    })?;

    if shmaddr != 0 && addr != shmaddr {
        tracing::debug!("Could not fit shared memory section at: {:#0x}", shmaddr);
        return Err(errno::EINVAL.into());
    }

    // @todo: check permissions of page
    let _ = shmflg;

    for (i, page) in shmem.physical_pages.iter().enumerate() {
        assert!(ctx.cpu.mem().map_physical(addr + i as u64 * sys::PAGE_SIZE, *page));
    }

    shmem.nattach += 1;
    shmem.lpid = ctx.kernel.process.pid;
    ctx.kernel.process.ipc.shmem.insert(addr, shmid);

    tracing::debug!("Attached shared memory section: {} at {:#0x}", shmid, addr);
    Ok(addr)
}

pub fn shmat<C: LinuxCpu>(ctx: &mut Ctx<C>, shmid: u64, shmaddr: u64, shmflg: u64) -> LinuxResult {
    let raddr = do_shmat(ctx, shmid, shmaddr, shmflg)?;
    Ok(raddr)
}

pub fn shmdt<C: LinuxCpu>(ctx: &mut Ctx<C>, shmaddr: u64) -> LinuxResult {
    tracing::debug!("shmdt({:#0x})", shmaddr);

    match ctx.kernel.process.ipc.shmem.remove(&shmaddr) {
        Some(id) => {
            tracing::debug!("Detaching shared memory section: {} from {:#0x}", id, shmaddr);
            let shmem = ctx.kernel.ipc.shmem.get_mut(&id).unwrap();

            let size = shmem.physical_pages.len() as u64 * sys::PAGE_SIZE;
            assert!(ctx.cpu.mem().unmap(shmaddr, size));

            shmem.nattach -= 1;
            shmem.lpid = ctx.kernel.process.pid;
            ctx.kernel.ipc.maybe_destroy_shmem(ctx.cpu.mem(), id);
            Ok(0)
        }
        None => Err(errno::EINVAL.into()),
    }
}

pub fn shmget<C: LinuxCpu>(ctx: &mut Ctx<C>, key: u64, size: u64, shmflg: u64) -> LinuxResult {
    tracing::debug!("shmget({}, {:#0x}, {:#0x})", key, size, shmflg);

    if key == ipc::IPC_PRIVATE {
        tracing::warn!("IPC_PRIVATE not supported");
        return Err(errno::ENOSYS.into());
    }

    match ctx.kernel.ipc.shmem.get(&key) {
        None => {
            if shmflg & ipc::IPC_CREAT == 0 {
                return Err(errno::ENOENT.into());
            }

            let n_pages = align_up(size, sys::PAGE_SIZE) / sys::PAGE_SIZE;
            if n_pages == 0 {
                tracing::debug!("Expected non-zero num of pages for shmem");
                return Err(errno::EINVAL.into());
            }

            // @fixme: get perm from shmflg
            let perm = perm::MAP | perm::READ | perm::WRITE | perm::INIT;
            let physical_pages = ctx.cpu.mem().alloc_physical(n_pages as usize)?;
            for index in &physical_pages {
                let data = ctx.cpu.mem().get_physical_mut(*index).data_mut();
                data.perm.fill(perm);
            }

            tracing::debug!("Created shmem: {} ({} pages)", key, physical_pages.len());
            let mut shmem = Shmem::new(physical_pages);
            shmem.cpid = ctx.kernel.process.pid;
            shmem.perm = ctx.kernel.init_ipc_perm(key, shmflg);
            ctx.kernel.ipc.shmem.insert(key, shmem);
            Ok(key)
        }
        Some(_existing) => {
            if shmflg & ipc::IPC_CREAT != 0 && shmflg & ipc::IPC_EXCL != 0 {
                return Err(errno::EEXIST.into());
            }
            Ok(key)
        }
    }
}

fn shmctl<C: LinuxCpu>(ctx: &mut Ctx<C>, shmid: u64, cmd: u64, buf: u64) -> LinuxResult {
    macro_rules! shmctl_unimplemented {
        ($name:expr) => {{
            tracing::warn!("shmctl({}, {}, {}, {:#0x}) unimplemented", shmid, $name, cmd, buf);
            Err(errno::ENOSYS.into())
        }};
    }

    let (cmd, is_ipc_64) = ipc::parse_ctl_version(cmd);
    match cmd {
        ipc::IPC_RMID => {
            tracing::debug!("shmctl({}, IPC_RMID, {:#0x})", shmid, buf);
            let shmem = ctx.kernel.ipc.shmem.get_mut(&shmid).ok_or_else(|| {
                tracing::debug!("shmid: {} not found", shmid);
                errno::EINVAL
            })?;

            shmem.destroy = true;
            ctx.kernel.ipc.maybe_destroy_shmem(ctx.cpu.mem(), shmid);

            Ok(0)
        }
        ipc::IPC_SET => shmctl_unimplemented!("IPC_SET"),
        ipc::IPC_STAT => {
            tracing::debug!("shmctl({}, IPC_STAT, {:#0x})", shmid, buf);

            let shmem = ctx.kernel.ipc.shmem.get(&shmid).ok_or_else(|| {
                tracing::debug!("shmid: {} not found", shmid);
                errno::EINVAL
            })?;

            if is_ipc_64 {
                let mut shm_id = types::ShmId64::default();
                shm_id.ipc_perm.key.value = shmid; // Key is currently the same as the ID.
                shm_id.ipc_perm.uid.value = shmem.perm.uid;
                shm_id.ipc_perm.gid.value = shmem.perm.gid;
                shm_id.ipc_perm.cuid.value = shmem.perm.cuid;
                shm_id.ipc_perm.cgid.value = shmem.perm.cgid;
                shm_id.ipc_perm.mode.value = shmem.perm.mode;
                shm_id.ipc_perm.seq.value = 0;

                shm_id.shm_segsz.value = shmem.physical_pages.len() as u64 * sys::PAGE_SIZE;

                shm_id.shm_atime.value = 5;
                shm_id.shm_dtime.value = 6;
                shm_id.shm_ctime.value = 7;
                shm_id.shm_cpid.value = shmem.cpid;
                shm_id.shm_lpid.value = shmem.lpid;

                shm_id.shm_nattch.value = shmem.nattach;

                shm_id.shm_unused4.value = 0x40404040_40404040;
                shm_id.shm_unused5.value = 0x50505050_50505050;

                ctx.write_user_struct(buf, &shm_id)?;
                Ok(0)
            }
            else {
                let mut shm_id = types::ShmId::default();
                shm_id.ipc_perm.key.value = shmid;
                shm_id.shm_segsz.value = shmem.physical_pages.len() as u64 * sys::PAGE_SIZE;
                shm_id.shm_nattch.value = 1;

                ctx.write_user_struct(buf, &shm_id)?;
                Ok(0)
            }
        }
        ipc::IPC_INFO => shmctl_unimplemented!("IPC_INFO"),

        ipc::shmem::LOCK => shmctl_unimplemented!("LOCK"),
        ipc::shmem::UNLOCK => shmctl_unimplemented!("UNLOCK"),

        ipc::shmem::STAT => shmctl_unimplemented!("STAT"),
        ipc::shmem::INFO => shmctl_unimplemented!("INFO"),
        ipc::shmem::STAT_ANY => shmctl_unimplemented!("STAT_ANY"),

        _ => Err(errno::EINVAL.into()),
    }
}

pub fn alarm<C: LinuxCpu>(ctx: &mut Ctx<C>, seconds: u64) -> LinuxResult {
    const INSTRUCTION_PER_SECOND: u64 = 1_000_000; // 1 MHz

    // Get time remaining with previous alarm
    let remaining_time = match ctx.kernel.process.timer.alarm {
        Some(timeout) => timeout.saturating_sub(ctx.cpu.i_count()) / INSTRUCTION_PER_SECOND,
        None => 0,
    };

    if seconds == 0 {
        // Just clear any previous alarm
        ctx.kernel.process.timer.alarm = None;
    }
    else {
        ctx.kernel.process.timer.alarm = Some(ctx.cpu.i_count() + seconds * INSTRUCTION_PER_SECOND);
    }

    Ok(remaining_time)
}

pub fn time<T: CDataType, C: LinuxCpu>(ctx: &mut Ctx<C>, tloc: u64) -> LinuxResult {
    let time_sec = ctx.kernel.current_time.as_secs();
    if tloc == NULL_PTR {
        return Ok(time_sec);
    }

    if let Err(e) = ctx.kernel.arch.libc(tloc).write::<T, _>(ctx.cpu.mem(), time_sec) {
        // Errors from this syscall are indistinguishable from negative time values, so this fault
        // will be lost if we return it in an exit code, so instead raise an access violation.
        //
        // NOTE: on modern x86 Linux kernels, `time` is implemented using a VDSO, which will result
        // in a fault like this.
        //
        // TODO: report as a signal.
        // return Err((Exit::MemError(e), tloc).into());
        return Err(VmExit::UnhandledException((ExceptionCode::from_store_error(e), tloc)).into());
    }
    Ok(time_sec)
}

mod clock {
    pub const CLOCK_REALTIME: u64 = 0;
    pub const CLOCK_MONOTONIC: u64 = 1;
}

pub fn clock_gettime<C: LinuxCpu>(ctx: &mut Ctx<C>, clk_id: u64, tp: u64) -> LinuxResult {
    let time = match clk_id {
        clock::CLOCK_REALTIME | clock::CLOCK_MONOTONIC => Timespec {
            seconds: ctx.kernel.current_time.as_secs() as i64,
            nanoseconds: ctx.kernel.current_time.subsec_nanos() as i64,
        },
        _ => return Err(errno::EINVAL.into()),
    };

    ctx.kernel.buffer.clear();
    time.encode(ctx.kernel.arch.triple.architecture, &mut ctx.kernel.buffer);
    ctx.cpu.mem().write_bytes(tp, &ctx.kernel.buffer)?;
    Ok(0)
}

pub fn clock_gettime32<C: LinuxCpu>(_ctx: &mut Ctx<C>, _clk_id: u64, _tp: u64) -> LinuxResult {
    tracing::warn!("clock_gettime32 unimplemented");
    Err(errno::ENOSYS.into())
}

pub fn clock_settime<C: LinuxCpu>(_ctx: &mut Ctx<C>, _clk_id: u64, _tp: u64) -> LinuxResult {
    tracing::warn!("clock_settime unimplemented");
    Err(errno::ENOSYS.into())
}

pub fn clock_settime32<C: LinuxCpu>(ctx: &mut Ctx<C>, clk_id: u64, tp: u64) -> LinuxResult {
    match clk_id {
        clock::CLOCK_REALTIME => {
            let time: types::Timespec32 = ctx.read_user_struct(tp)?;
            ctx.kernel.current_time =
                std::time::Duration::new(time.tv_sec.value, time.tv_nsec.value as u32);
            tracing::debug!("CLOCK_REALTIME set to: {:?}", ctx.kernel.current_time);
            Ok(0)
        }
        _ => Err(errno::EINVAL.into()),
    }
}

pub fn clock_getres<C: LinuxCpu>(ctx: &mut Ctx<C>, clk_id: u64, res: u64) -> LinuxResult {
    let clock_res = match clk_id {
        clock::CLOCK_REALTIME | clock::CLOCK_MONOTONIC => {
            Timespec { seconds: 0, nanoseconds: 1000 } // 1ms precision
        }
        _ => return Err(errno::EINVAL.into()),
    };

    ctx.kernel.buffer.clear();
    clock_res.encode(ctx.kernel.arch.triple.architecture, &mut ctx.kernel.buffer);
    ctx.cpu.mem().write_bytes(res, &ctx.kernel.buffer)?;

    Ok(0)
}

const UTC_TIMEZONE: Timezone = Timezone { minuteswest: 0, dsttime: 0 };

pub fn gettimeofday<C: LinuxCpu>(ctx: &mut Ctx<C>, tv: u64, tz: u64) -> LinuxResult {
    if tv != NULL_PTR {
        ctx.kernel.buffer.clear();
        let time = Timeval {
            seconds: ctx.kernel.current_time.as_secs() as i64,
            microseconds: ctx.kernel.current_time.subsec_micros() as i64,
        };
        time.encode(ctx.kernel.arch.triple.architecture, &mut ctx.kernel.buffer);
        ctx.cpu.mem().write_bytes(tv, &ctx.kernel.buffer)?;
    }

    if tz != NULL_PTR {
        ctx.kernel.buffer.clear();
        UTC_TIMEZONE.encode(ctx.kernel.arch.triple.architecture, &mut ctx.kernel.buffer);
        ctx.cpu.mem().write_bytes(tz, &ctx.kernel.buffer)?;
    }

    Ok(0)
}

pub fn nanosleep<C: LinuxCpu>(ctx: &mut Ctx<C>, req: u64, rem: u64) -> LinuxResult {
    // @fixme: use correct timespec size on 64-bit platforms
    nanosleep_time32(ctx, req, rem)
}

pub fn nanosleep_time32<C: LinuxCpu>(ctx: &mut Ctx<C>, req: u64, rem: u64) -> LinuxResult {
    let req_time: types::Timespec32 = ctx.read_user_struct(req)?;
    let duration = std::time::Duration::new(req_time.tv_sec.value, req_time.tv_nsec.value as u32);

    // Check if process was previously timed out
    if ctx.kernel.process.timeout.is_some() {
        // Notify the user that there is zero remaining to sleep for.
        ctx.write_user_struct(rem, &types::Timespec32::default())?;
        return Ok(0);
    }

    ctx.kernel.process.timeout = Some(duration);
    ctx.kernel.switch_task(ctx.cpu, crate::PauseReason::WaitFile)
}

pub const ITIMER_REAL: u64 = 0;
pub const ITIMER_VIRTUAL: u64 = 1;
pub const ITIMER_PROF: u64 = 2;

pub fn setitimer<C: LinuxCpu>(ctx: &mut Ctx<C>, which: u64, curr_value: u64) -> LinuxResult {
    let _value: types::itimerval = ctx.read_user_struct(curr_value)?;

    // @todo: implement alarms from timers.
    match which {
        ITIMER_REAL => Ok(0),
        ITIMER_VIRTUAL => Ok(0),
        ITIMER_PROF => Ok(0),
        _ => Err(errno::EINVAL.into()),
    }
}

pub fn getrandom<C: LinuxCpu>(ctx: &mut Ctx<C>, buf: u64, buflen: u64, flags: u64) -> LinuxResult {
    // We don't care about the flags since we never block and only have one rng source
    let _flags = flags;

    let random = &mut ctx.kernel.random;
    let mut offset = 0;
    while offset < buflen {
        let num_bytes = (buflen - offset).min(256);

        ctx.kernel.buffer.clear();
        ctx.kernel.buffer.extend((0..num_bytes).map(|_| random.next()));

        ctx.cpu.mem().write_bytes(buf.wrapping_add(offset), &ctx.kernel.buffer)?;

        offset += num_bytes;
    }

    Ok(buflen)
}

pub fn sigaltstack<C: LinuxCpu>(_ctx: &mut Ctx<C>, _ss: u64, _old_ss: u64) -> LinuxResult {
    Err(errno::ENOSYS.into())
}

pub fn rt_sigaction<C: LinuxCpu>(
    ctx: &mut Ctx<C>,
    signum: u64,
    act: u64,
    oldact: u64,
) -> LinuxResult {
    if signum >= 64 {
        return Err(errno::EINVAL.into());
    }

    if oldact != NULL_PTR {
        let act = ctx.kernel.process.signal_handlers.entries[signum as usize];
        ctx.write_user_struct(oldact, &act)?;
    }

    if act != NULL_PTR {
        let act = ctx.read_user_struct::<types::Sigaction>(act)?;
        ctx.kernel.process.signal_handlers.set_action(signum, act);
    }

    Ok(0)
}

pub fn rt_sigprocmask<C: LinuxCpu>(
    _ctx: &mut Ctx<C>,
    _how: u64,
    _set: u64,
    _oldset: u64,
    _sigsetsize: u64,
) -> LinuxResult {
    tracing::warn!("rt_sigprocmask ignored");
    Ok(0)
}

pub fn rt_sigsuspend<C: LinuxCpu>(ctx: &mut Ctx<C>, mask: u64) -> LinuxResult {
    let mask = ctx.read_user_struct::<types::libc::ulonglong>(mask)?.value;
    let pending = ctx.kernel.process.pending_signals;

    tracing::debug!("sigsuspend mask = {:#0x}, pending_signals: {:#0x}", mask, pending);
    if pending & (!mask) != 0 {
        return Err(errno::EINTR.into());
    }
    ctx.kernel.switch_task(ctx.cpu, crate::PauseReason::WaitSignal)
}

pub fn rt_sigreturn<C: LinuxCpu>(ctx: &mut Ctx<C>) -> LinuxResult {
    ctx.kernel.arch.dynamic.restore_signal_frame(ctx.cpu)?;
    Ok(0)
}
