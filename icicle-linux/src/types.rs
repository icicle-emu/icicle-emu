//! Structure definitions for structures read from/written to user space.
//!
//! There are two approaches we use:
//!
//! - Define each structure with the largest possible field values for any supported architecture,
//!   and manually serialize/deserialize to the correct encoding for each architecture
//! - Define each structure to be generic in terms of the types defined in the `arch` module.
#![allow(bad_style, unused)]

// @fixme: Some cases of `ULong` should be `size_t` instead;

use std::convert::TryFrom;

use icicle_cpu::mem::MemResult;
use target_lexicon::Architecture;

use crate::{
    arch::{self, Value},
    LinuxMmu,
};

// @fixme: update structs below to use these types.
pub mod libc {
    use crate::arch::{self, Value};

    pub type intptr_t = Value<arch::Ptr>;

    pub type int = Value<arch::SInt>;
    pub type ulong = Value<arch::ULong>;
    pub type size_t = Value<arch::ULong>;
    pub type ulonglong = Value<arch::ULongLong>;

    pub type socklen_t = Value<arch::U32>;
}

/// A macro for generate read/write helpers that can be used to interact with types in user-space in
/// an architecture independent way.
macro_rules! libc_struct {
    ($(#[$attr:meta])* $vis:vis struct $name:ident {
            $($field_vis:vis $field_name:ident: $field_ty:ty),*$(,)?
    }) => {
        $(#[$attr])*
        $vis struct $name {
            $($field_vis $field_name: $field_ty),*
        }

        impl arch::Struct for $name {
            fn read<M: LinuxMmu>(libc: &mut arch::Libc, mem: &mut M) -> MemResult<Self> {
                Ok(Self {
                    $($field_name: libc.read_struct(mem)?),*
                })
            }

            fn write<M: LinuxMmu>(&self, libc: &mut arch::Libc, mem: &mut M) -> MemResult<()> {
                $(libc.write_struct(mem, &self.$field_name)?;)*
                Ok(())
            }
        }
    }
}

libc_struct!(
    pub struct PollFd {
        pub fd: Value<arch::SInt>,
        pub events: Value<arch::SShort>,
        pub revents: Value<arch::SShort>,
    }
);

libc_struct!(
    pub struct SemBuf {
        pub sem_num: Value<arch::UShort>,
        pub sem_op: Value<arch::SShort>,
        pub sem_flg: Value<arch::SShort>,
    }
);

libc_struct!(
    #[derive(Default)]
    pub struct ShmId {
        pub ipc_perm: IpcPerm,
        pub shm_segsz: Value<arch::SInt>,
        pub shm_atime: Value<arch::SLong>,
        pub shm_dtime: Value<arch::SLong>,
        pub shm_ctime: Value<arch::SLong>,
        pub shm_cpid: Value<arch::SInt>,
        pub shm_lpid: Value<arch::SInt>,
        pub shm_nattch: Value<arch::UShort>,
        pub shm_unused: Value<arch::UShort>,
        pub shm_unused2: Value<arch::Ptr>,
        pub shm_unused3: Value<arch::Ptr>,
    }
);

libc_struct!(
    #[derive(Default)]
    pub struct IpcPerm {
        pub key: Value<arch::SInt>,
        pub uid: Value<arch::UInt>,
        pub gid: Value<arch::UInt>,
        pub cuid: Value<arch::UInt>,
        pub cgid: Value<arch::UInt>,
        pub mode: Value<arch::UInt>,
        pub seq: Value<arch::UShort>,
    }
);

libc_struct!(
    #[derive(Default)]
    pub struct ShmId64 {
        pub ipc_perm: IpcPerm64,
        pub shm_segsz: libc::size_t,
        pub shm_atime: Value<arch::ULong>,
        // pub shm_atime_high: Value<arch::ULong>,
        pub shm_dtime: Value<arch::ULong>,
        // pub shm_dtime_high: Value<arch::ULong>,
        pub shm_ctime: Value<arch::ULong>,
        // pub shm_ctime_high: Value<arch::ULong>,
        pub shm_cpid: Value<arch::SInt>,
        pub shm_lpid: Value<arch::SInt>,
        pub shm_nattch: Value<arch::ULong>,
        pub shm_unused4: Value<arch::ULong>,
        pub shm_unused5: Value<arch::ULong>,
    }
);

libc_struct!(
    #[derive(Default)]
    pub struct IpcPerm64 {
        pub key: Value<arch::SInt>,
        pub uid: Value<arch::UInt>,
        pub gid: Value<arch::UInt>,
        pub cuid: Value<arch::UInt>,
        pub cgid: Value<arch::UInt>,
        pub mode: Value<arch::UShort>,
        pub _pad1: Value<arch::UShort>,
        pub seq: Value<arch::UShort>,
        pub _pad2: Value<arch::UShort>,
        pub _unused1: Value<arch::UInt>,
        pub _unused2: Value<arch::UInt>,
    }
);

#[derive(Debug, Default, Clone, Copy)]
pub struct Sigaction {
    pub handler: Value<arch::SLong>,
    pub flags: Value<arch::ULong>,
    pub restorer: Value<arch::Ptr>,
    pub mask: Sigset,
}

// need a custom implementation because order is different on different architectures.
impl arch::Struct for Sigaction {
    fn read<M: LinuxMmu>(libc: &mut arch::Libc, mem: &mut M) -> MemResult<Self> {
        let mut action = Sigaction::default();

        match libc.arch {
            Architecture::Mips32(_) | Architecture::Mips64(_) => {
                action.flags = libc.read_struct(mem)?;
                action.handler = libc.read_struct(mem)?;
                action.restorer = libc.read_struct(mem)?;
                action.mask = libc.read_struct(mem)?;
                if libc.data_model.pointer_width().bits() < 64 {
                    let _pad1 = libc.read::<arch::SInt, _>(mem)?;
                }
            }

            // @fixme: there are probably other architectures where this is different.
            _ => {
                action.handler = libc.read_struct(mem)?;
                action.flags = libc.read_struct(mem)?;
                action.restorer = libc.read_struct(mem)?;
                action.mask = libc.read_struct(mem)?;
            }
        }

        Ok(action)
    }

    fn write<M: LinuxMmu>(&self, libc: &mut arch::Libc, mem: &mut M) -> MemResult<()> {
        match libc.arch {
            Architecture::Mips32(_) | Architecture::Mips64(_) => {
                libc.write_struct(mem, &self.flags)?;
                libc.write_struct(mem, &self.handler)?;
                libc.write_struct(mem, &self.restorer)?;
                libc.write_struct(mem, &self.mask)?;

                if libc.data_model.pointer_width().bits() < 64 {
                    libc.write::<arch::SInt, _>(mem, 0)?;
                }
            }

            // @fixme: there are probably other architectures where this is different.
            _ => {
                libc.write_struct(mem, &self.handler)?;
                libc.write_struct(mem, &self.flags)?;
                libc.write_struct(mem, &self.restorer)?;
                libc.write_struct(mem, &self.mask)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Sigset {
    pub value: [u8; 64 / 8],
}

impl arch::Struct for Sigset {
    fn read<M: LinuxMmu>(libc: &mut arch::Libc, mem: &mut M) -> MemResult<Self> {
        let mut value = [0; 64 / 8];
        let bytes_per_word = libc.data_model.long_size().bytes();

        for chunk in value.chunks_exact_mut(bytes_per_word as usize) {
            // @fixme: byteswap
            libc.read_bytes(mem, chunk)?;
        }

        Ok(Self { value })
    }

    fn write<M: LinuxMmu>(&self, libc: &mut arch::Libc, mem: &mut M) -> MemResult<()> {
        let bytes_per_word = libc.data_model.long_size().bytes();

        for chunk in self.value.chunks_exact(bytes_per_word as usize) {
            // @fixme: byteswap
            libc.write_bytes(mem, chunk)?;
        }

        Ok(())
    }
}

libc_struct!(
    pub struct IoVec {
        pub base: libc::intptr_t,
        pub len: libc::size_t,
    }
);

libc_struct!(
    #[derive(Clone, Debug)]
    pub struct MsgHdr {
        pub name: libc::intptr_t,
        pub namelen: libc::socklen_t,
        pub iov: libc::intptr_t,
        pub iovlen: libc::size_t,
        pub control: libc::intptr_t,
        pub controllen: libc::size_t,
        pub flags: libc::int,
    }
);

#[derive(Copy, Clone, Default, Debug)]
pub struct Stat {
    /// Id of device containing file
    pub dev: u64,

    /// Inode number
    pub ino: u64,

    /// Protection bit map
    pub mode: u32,

    /// Number of hardlinks
    pub nlink: u64,

    /// user ID of owner
    pub uid: u32,

    /// group ID of owner
    pub gid: u32,

    /// device ID (if special file)
    pub rdev: u64,

    /// total size, in bytes
    pub size: i64,

    /// blocksize for file system I/O
    pub blksize: i64,

    /// number of 512B blocks allocated
    pub blocks: i64,

    /// time of last access
    pub atime: i64,
    pub atime_nsec: i64,

    /// time of last modification
    pub mtime: i64,
    pub mtime_nsec: i64,

    /// time of last status change
    pub ctime: i64,
    pub ctime_nsec: i64,
}

impl Stat {
    pub fn debug_stat() -> Self {
        Self {
            dev: 0x12_12,
            ino: 1234567,
            mode: 0o777,
            nlink: 1,
            uid: 1,
            gid: 1,
            size: 0,
            blocks: 0,
            blksize: 512,
            ..Self::new()
        }
    }

    pub const fn new() -> Self {
        Self {
            dev: 0,
            ino: 0,
            mode: 0,
            nlink: 0,
            uid: 0,
            gid: 0,
            rdev: 0,
            size: 0,
            blksize: 1,
            blocks: 0,
            atime: 1,
            atime_nsec: 0,
            mtime: 1,
            mtime_nsec: 0,
            ctime: 1,
            ctime_nsec: 0,
        }
    }
}

impl Stat {
    pub fn encode_stat64(&self, arch: Architecture, buf: &mut Vec<u8>) {
        match arch {
            Architecture::X86_64 => {
                let native_stat64 = x64::stat64 {
                    st_dev: self.dev,
                    st_ino: self.ino,
                    st_nlink: self.nlink,
                    st_mode: self.mode,
                    st_uid: self.uid,
                    st_gid: self.gid,
                    st_rdev: self.rdev,
                    st_size: self.size,
                    st_blksize: self.blksize,
                    st_blocks: self.blocks,
                    st_atim: generic64::timespec { tv_sec: self.atime, tv_nsec: self.atime_nsec },
                    st_mtim: generic64::timespec { tv_sec: self.mtime, tv_nsec: self.mtime_nsec },
                    st_ctim: generic64::timespec { tv_sec: self.ctime, tv_nsec: self.ctime_nsec },
                    ..x64::stat64::default()
                };
                assert_eq!(std::mem::size_of::<x64::stat64>(), 0x90);
                buf.extend_from_slice(bytemuck::bytes_of(&native_stat64));
            }
            Architecture::Mips32(target_lexicon::Mips32Architecture::Mipsel) => {
                let native_stat64 = mips32::stat64 {
                    st_dev: self.dev as u32,
                    st_ino: self.ino,
                    st_nlink: self.nlink as u32,
                    st_mode: self.mode,
                    st_uid: self.uid,
                    st_gid: self.gid,
                    st_rdev: self.rdev as u32,
                    st_size: self.size,
                    st_blksize: self.blksize as i32,
                    st_blocks: self.blocks,
                    st_atim: mips32::timespec {
                        tv_sec: self.atime as i32,
                        tv_nsec: self.atime_nsec as i32,
                    },
                    st_mtim: mips32::timespec {
                        tv_sec: self.mtime as i32,
                        tv_nsec: self.mtime_nsec as i32,
                    },
                    st_ctim: mips32::timespec {
                        tv_sec: self.ctime as i32,
                        tv_nsec: self.ctime_nsec as i32,
                    },
                    ..mips32::stat64::default()
                };
                buf.extend_from_slice(bytemuck::bytes_of(&native_stat64));
            }
            Architecture::Mips32(target_lexicon::Mips32Architecture::Mips) => {
                let native_stat64 = mips32::stat64 {
                    st_dev: (self.dev as u32).swap_bytes(),
                    st_ino: (self.ino).swap_bytes(),
                    st_nlink: (self.nlink as u32).swap_bytes(),
                    st_mode: (self.mode).swap_bytes(),
                    st_uid: (self.uid).swap_bytes(),
                    st_gid: (self.gid).swap_bytes(),
                    st_rdev: (self.rdev as u32).swap_bytes(),
                    st_size: (self.size).swap_bytes(),
                    st_blksize: (self.blksize as i32).swap_bytes(),
                    st_blocks: (self.blocks).swap_bytes(),
                    st_atim: mips32::timespec {
                        tv_sec: (self.atime as i32).swap_bytes(),
                        tv_nsec: (self.atime_nsec as i32).swap_bytes(),
                    },
                    st_mtim: mips32::timespec {
                        tv_sec: (self.mtime as i32).swap_bytes(),
                        tv_nsec: (self.mtime_nsec as i32).swap_bytes(),
                    },
                    st_ctim: mips32::timespec {
                        tv_sec: (self.ctime as i32).swap_bytes(),
                        tv_nsec: (self.ctime_nsec as i32).swap_bytes(),
                    },
                    ..mips32::stat64::default()
                };
                buf.extend_from_slice(bytemuck::bytes_of(&native_stat64));
            }
            arch if arch.pointer_width().map_or(false, |x| x.bits() == 64) => {
                let native_stat = generic64::stat {
                    st_dev: self.dev,
                    st_ino: self.ino,
                    st_nlink: self.nlink as u32,
                    st_mode: self.mode,
                    st_uid: self.uid,
                    st_gid: self.gid,
                    st_rdev: self.rdev,
                    st_size: self.size,
                    st_blksize: self.blksize as i32,
                    st_blocks: self.blocks,
                    st_atime: self.atime,
                    st_atime_nsec: self.atime_nsec as u64,
                    st_mtime: self.mtime,
                    st_mtime_nsec: self.mtime_nsec as u64,
                    st_ctime: self.ctime,
                    st_ctime_nsec: self.ctime_nsec as u64,
                    ..generic64::stat::default()
                };
                assert_eq!(std::mem::size_of::<generic64::stat>(), 0x80);
                buf.extend_from_slice(bytemuck::bytes_of(&native_stat));
            }
            _ => unimplemented!("stat64 not implemented for this architecture"),
        }
    }

    pub fn encode_stat(&self, arch: Architecture, buf: &mut Vec<u8>) {
        match arch {
            arch if arch.pointer_width().map_or(false, |x| x.bits() == 64) => {
                self.encode_stat64(arch, buf)
            }
            Architecture::Mips32(target_lexicon::Mips32Architecture::Mipsel) => {
                let native_stat = mips32::stat {
                    st_dev: self.dev as u32,
                    st_ino: self.ino as u32,
                    st_nlink: self.nlink as u32,
                    st_mode: self.mode,
                    st_uid: self.uid,
                    st_gid: self.gid,
                    st_rdev: self.rdev as u32,
                    st_size: self.size as i32,
                    st_blksize: self.blksize as i32,
                    st_blocks: self.blocks as i32,
                    st_atim: mips32::timespec {
                        tv_sec: self.atime as i32,
                        tv_nsec: self.atime_nsec as i32,
                    },
                    st_mtim: mips32::timespec {
                        tv_sec: self.mtime as i32,
                        tv_nsec: self.mtime_nsec as i32,
                    },
                    st_ctim: mips32::timespec {
                        tv_sec: self.ctime as i32,
                        tv_nsec: self.ctime_nsec as i32,
                    },
                    ..mips32::stat::default()
                };
                buf.extend_from_slice(bytemuck::bytes_of(&native_stat));
            }
            Architecture::Mips32(target_lexicon::Mips32Architecture::Mips) => {
                let native_stat = mips32::stat {
                    st_dev: (self.dev as u32).swap_bytes(),
                    st_ino: (self.ino as u32).swap_bytes(),
                    st_nlink: (self.nlink as u32).swap_bytes(),
                    st_mode: (self.mode).swap_bytes(),
                    st_uid: (self.uid).swap_bytes(),
                    st_gid: (self.gid).swap_bytes(),
                    st_rdev: (self.rdev as u32).swap_bytes(),
                    st_size: (self.size as i32).swap_bytes(),
                    st_blksize: (self.blksize as i32).swap_bytes(),
                    st_blocks: (self.blocks as i32).swap_bytes(),
                    st_atim: mips32::timespec {
                        tv_sec: (self.atime as i32).swap_bytes(),
                        tv_nsec: (self.atime_nsec as i32).swap_bytes(),
                    },
                    st_mtim: mips32::timespec {
                        tv_sec: (self.mtime as i32).swap_bytes(),
                        tv_nsec: (self.mtime_nsec as i32).swap_bytes(),
                    },
                    st_ctim: mips32::timespec {
                        tv_sec: (self.ctime as i32).swap_bytes(),
                        tv_nsec: (self.ctime_nsec as i32).swap_bytes(),
                    },
                    ..mips32::stat::default()
                };
                buf.extend_from_slice(bytemuck::bytes_of(&native_stat));
            }

            _ => unimplemented!("stat64 not implemented for this architecture"),
        }
    }
}

libc_struct!(
    #[derive(Default)]
    pub struct TimespecVal {
        pub tv_sec: Value<arch::SLong>,
        pub tv_nsec: Value<arch::SLong>,
    }
);

libc_struct!(
    #[derive(Default)]
    pub struct Timespec32 {
        pub tv_sec: Value<arch::S32>,
        pub tv_nsec: Value<arch::S32>,
    }
);

pub struct Timespec {
    pub seconds: i64,
    pub nanoseconds: i64,
}

impl Timespec {
    pub fn encode(&self, arch: Architecture, buf: &mut Vec<u8>) {
        match arch {
            arch if arch.pointer_width().map_or(false, |x| x.bits() == 64) => {
                let data = generic64::timespec { tv_sec: self.seconds, tv_nsec: self.nanoseconds };
                buf.extend_from_slice(bytemuck::bytes_of(&data));
            }
            Architecture::Mips32(target_lexicon::Mips32Architecture::Mipsel) => {
                let data = mips32::timespec {
                    tv_sec: self.seconds as i32,
                    tv_nsec: self.nanoseconds as i32,
                };
                buf.extend_from_slice(bytemuck::bytes_of(&data))
            }
            Architecture::Mips32(target_lexicon::Mips32Architecture::Mips) => {
                let data = mips32::timespec {
                    tv_sec: (self.seconds as i32).swap_bytes(),
                    tv_nsec: (self.nanoseconds as i32).swap_bytes(),
                };
                buf.extend_from_slice(bytemuck::bytes_of(&data))
            }

            _ => unimplemented!("timespec not implemented for this architecture"),
        }
    }
}

pub struct Timeval {
    pub seconds: i64,
    pub microseconds: i64,
}

impl Timeval {
    pub fn encode(&self, arch: Architecture, buf: &mut Vec<u8>) {
        match arch {
            arch if arch.pointer_width().map_or(false, |x| x.bits() == 64) => {
                let data = generic64::timeval {
                    tv_sec: self.seconds as i32,
                    tv_usec: self.microseconds as i32,
                };
                buf.extend_from_slice(bytemuck::bytes_of(&data));
            }

            Architecture::Mips32(target_lexicon::Mips32Architecture::Mipsel) => {
                let data = mips32::timeval {
                    tv_sec: self.seconds as i32,
                    tv_usec: self.microseconds as i32,
                };
                buf.extend_from_slice(bytemuck::bytes_of(&data))
            }
            Architecture::Mips32(target_lexicon::Mips32Architecture::Mips) => {
                let data = mips32::timeval {
                    tv_sec: (self.seconds as i32).swap_bytes(),
                    tv_usec: (self.microseconds as i32).swap_bytes(),
                };
                buf.extend_from_slice(bytemuck::bytes_of(&data))
            }
            _ => unimplemented!("timeval not implemented for this architecture"),
        }
    }
}

pub struct Timezone {
    pub minuteswest: i32,
    pub dsttime: i32,
}

impl Timezone {
    pub fn encode(&self, arch: Architecture, buf: &mut Vec<u8>) {
        match arch {
            arch if arch.pointer_width().map_or(false, |x| x.bits() == 64) => {
                let data = generic64::timezone {
                    tz_minuteswest: self.minuteswest,
                    tz_dsttime: self.dsttime,
                };
                buf.extend_from_slice(bytemuck::bytes_of(&data));
            }
            _ => unimplemented!("timezone not implemented for this architecture"),
        }
    }
}

libc_struct!(
    #[derive(Default)]
    pub struct itimerval {
        pub it_interval: TimespecVal,
        pub it_value: TimespecVal,
    }
);

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Seek {
    /// Set absolute file offset
    Set,

    /// Set file offset relative to the current position
    Cur,

    /// Set file offset relative to the end of the file
    End,

    Data,
    Hole,
}

impl TryFrom<u64> for Seek {
    type Error = u64;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Seek::Set),
            1 => Ok(Seek::Cur),
            2 => Ok(Seek::End),
            3 => Ok(Seek::Data),
            4 => Ok(Seek::Hole),
            _ => Err(crate::errno::EINVAL),
        }
    }
}

pub type int16_t = i16;
pub type int32_t = i32;
pub type int64_t = i64;

pub type uint8_t = u8;
pub type uint16_t = u16;
pub type uint32_t = u32;
pub type uint64_t = u64;

pub type pid_t = int32_t;
pub type uid_t = uint32_t;
pub type gid_t = uint32_t;
pub type socklen_t = uint32_t;
pub type dev_t = uint64_t;
pub type mode_t = uint32_t;

pub type int = int32_t;
pub type unsigned_int = uint32_t;

mod generic64 {
    use super::*;

    pub type ulong = u64;
    pub type long = i64;
    pub type short = i16;

    pub type time_t = i64;
    pub type ino_t = u64;
    pub type ino64_t = u64;
    pub type nlink_t = u64;
    pub type off_t = i64;
    pub type off64_t = i64;
    pub type blksize_t = long;
    pub type blkcnt_t = long;
    pub type blkcnt64_t = long;

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    pub struct timespec {
        pub tv_sec: time_t,
        pub tv_nsec: long,
    }

    unsafe impl bytemuck::Zeroable for timespec {}
    unsafe impl bytemuck::Pod for timespec {}

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    pub struct timeval {
        pub tv_sec: i32,
        pub tv_usec: i32,
    }

    unsafe impl bytemuck::Zeroable for timeval {}
    unsafe impl bytemuck::Pod for timeval {}

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    pub struct timezone {
        pub tz_minuteswest: i32,
        pub tz_dsttime: i32,
    }

    unsafe impl bytemuck::Zeroable for timezone {}
    unsafe impl bytemuck::Pod for timezone {}

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    pub struct __exit_status {
        e_termination: short,
        e_exit: short,
    }

    unsafe impl bytemuck::Zeroable for __exit_status {}
    unsafe impl bytemuck::Pod for __exit_status {}

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct utmpx {
        ut_type: short,
        ut_pid: pid_t,
        ut_line: [u8; 32],
        ut_id: [u8; 4],
        ut_user: [u8; 32],
        ut_host: [u8; 256],
        ut_exit: __exit_status,
        ut_session: i32,
        ut_tv: timeval,
        ut_addr_v6: [i32; 4],
    }

    unsafe impl bytemuck::Zeroable for utmpx {}
    unsafe impl bytemuck::Pod for utmpx {}

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    pub struct stat {
        pub st_dev: ulong,
        pub st_ino: ulong,
        pub st_nlink: unsigned_int,
        pub st_mode: unsigned_int,
        pub st_uid: unsigned_int,
        pub st_gid: unsigned_int,
        pub st_rdev: ulong,
        pub __pad1: ulong,
        pub st_size: long,
        pub st_blksize: int,
        pub __pad2: int,
        pub st_blocks: long,
        pub st_atime: long,
        pub st_atime_nsec: ulong,
        pub st_mtime: long,
        pub st_mtime_nsec: ulong,
        pub st_ctime: long,
        pub st_ctime_nsec: ulong,
        pub __unused4: unsigned_int,
        pub __unused5: unsigned_int,
    }

    unsafe impl bytemuck::Zeroable for stat {}
    unsafe impl bytemuck::Pod for stat {}
}

mod x64 {
    use super::{generic64::*, *};

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    pub struct stat64 {
        pub st_dev: dev_t,
        pub st_ino: ino64_t,
        pub st_nlink: nlink_t,
        pub st_mode: mode_t,
        pub st_uid: uid_t,
        pub st_gid: gid_t,
        pub __pad0: int,
        pub st_rdev: dev_t,
        pub st_size: off64_t,
        pub st_blksize: blksize_t,
        pub st_blocks: blkcnt64_t,
        pub st_atim: timespec,
        pub st_mtim: timespec,
        pub st_ctim: timespec,
        pub __unused3: [long; 3],
    }

    unsafe impl bytemuck::Zeroable for stat64 {}
    unsafe impl bytemuck::Pod for stat64 {}
}

mod mips32 {
    use super::*;

    pub type uint = u32;
    pub type ulong = u32;
    pub type long = i32;

    pub type time_t = i32;
    pub type dev_t = uint;
    pub type ino_t = ulong;
    pub type ino64_t = u64;
    pub type nlink_t = u32;
    pub type off_t = i32;
    pub type off64_t = i64;
    pub type blksize_t = long;
    pub type blkcnt_t = long;
    pub type blkcnt64_t = int64_t;

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    pub struct timespec {
        pub tv_sec: time_t,
        pub tv_nsec: long,
    }

    unsafe impl bytemuck::Zeroable for timespec {}
    unsafe impl bytemuck::Pod for timespec {}

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    pub struct timeval {
        pub tv_sec: i32,
        pub tv_usec: i32,
    }

    unsafe impl bytemuck::Zeroable for timeval {}
    unsafe impl bytemuck::Pod for timeval {}

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    pub struct stat64 {
        pub st_dev: ulong,
        pub __pad0: [ulong; 3],
        pub st_ino: ino64_t,
        pub st_mode: mode_t,
        pub st_nlink: nlink_t,
        pub st_uid: uid_t,
        pub st_gid: gid_t,
        pub st_rdev: ulong,
        pub __pad1: [ulong; 3],
        pub st_size: off64_t,
        pub st_atim: timespec,
        pub st_mtim: timespec,
        pub st_ctim: timespec,
        pub st_blksize: blksize_t,
        pub __pad2: [long; 1],
        pub st_blocks: blkcnt64_t,
    }

    unsafe impl bytemuck::Zeroable for stat64 {}
    unsafe impl bytemuck::Pod for stat64 {}

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    pub struct stat {
        pub st_dev: dev_t,
        pub st_pad1: [long; 3],
        pub st_ino: ino_t,
        pub st_mode: mode_t,
        pub st_nlink: nlink_t,
        pub st_uid: uid_t,
        pub st_gid: gid_t,
        pub st_rdev: dev_t,
        pub st_pad2: [long; 2],
        pub st_size: off_t,
        pub st_pad3: long,
        pub st_atim: timespec,
        pub st_mtim: timespec,
        pub st_ctim: timespec,
        pub st_blksize: blksize_t,
        pub st_blocks: blkcnt_t,
        pub st_pad4: [long; 14],
    }

    unsafe impl bytemuck::Zeroable for stat {}
    unsafe impl bytemuck::Pod for stat {}
}
