#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum MemError {
    Unallocated,
    Unmapped,
    UnmappedRegister,
    Uninitalized,
    ReadViolation,
    WriteViolation,
    ExecViolation,
    ReadWatch,
    WriteWatch,
    Unaligned,
    OutOfMemory,
    SelfModifyingCode,
    AddressOverflow,
    Unknown,
}

impl std::str::FromStr for MemError {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "Unmapped" => Self::Unmapped,
            "UnmappedRegister" => Self::UnmappedRegister,
            "Unallocated" => Self::Unallocated,
            "Uninitalized" => Self::Uninitalized,
            "ReadViolation" => Self::ReadViolation,
            "WriteViolation" => Self::WriteViolation,
            "ExecViolation" => Self::ExecViolation,
            "ReadWatch" => Self::ReadWatch,
            "WriteWatch" => Self::WriteWatch,
            "Unaligned" => Self::Unaligned,
            "OutOfMemory" => Self::OutOfMemory,
            "SelfModifyingCode" => Self::SelfModifyingCode,
            "AddressOverflow" => Self::AddressOverflow,
            _ => Self::Unknown,
        })
    }
}

impl MemError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unmapped => "Unmapped",
            Self::UnmappedRegister => "UnmappedRegister",
            Self::Unallocated => "Unallocated",
            Self::Uninitalized => "Uninitalized",
            Self::ReadViolation => "ReadViolation",
            Self::WriteViolation => "WriteViolation",
            Self::ExecViolation => "ExecViolation",
            Self::ReadWatch => "ReadWatch",
            Self::WriteWatch => "WriteWatch",
            Self::Unaligned => "Unaligned",
            Self::OutOfMemory => "OutOfMemory",
            Self::SelfModifyingCode => "SelfModifyingCode",
            Self::AddressOverflow => "AddressOverflow",
            Self::Unknown => "Unknown",
        }
    }

    pub const fn code(self) -> u64 {
        match self {
            Self::Unmapped => 0x1_0000,
            Self::Uninitalized => 0x1_0001,
            Self::ReadViolation => 0x1_0002,
            Self::WriteViolation => 0x1_0003,
            Self::ExecViolation => 0x1_0004,
            Self::ReadWatch => 0x1_0005,
            Self::WriteWatch => 0x1_0006,
            Self::Unallocated => 0x1_0007,
            Self::Unaligned => 0x1_0008,
            Self::OutOfMemory => 0x1_0009,
            Self::SelfModifyingCode => 0x1_000a,
            Self::AddressOverflow => 0x1_000b,
            Self::UnmappedRegister => 0x1_000c,
            Self::Unknown => 0x1_FFFF,
        }
    }

    pub const fn from_code(code: u64) -> MemError {
        match code {
            0x1_0000 => Self::Unmapped,
            0x1_0001 => Self::Uninitalized,
            0x1_0002 => Self::ReadViolation,
            0x1_0003 => Self::WriteViolation,
            0x1_0004 => Self::ExecViolation,
            0x1_0005 => Self::ReadWatch,
            0x1_0006 => Self::WriteWatch,
            0x1_0007 => Self::Unallocated,
            0x1_0008 => Self::Unaligned,
            0x1_0009 => Self::OutOfMemory,
            0x1_000a => Self::SelfModifyingCode,
            0x1_000b => Self::AddressOverflow,
            _ => Self::Unknown,
        }
    }
}

impl std::fmt::Display for MemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for MemError {}

pub type MemResult<T> = Result<T, MemError>;

pub const NONE: u8 = 0b0000_0000;
pub const INIT: u8 = 0b0000_0001;
pub const READ: u8 = 0b0000_0010;
pub const WRITE: u8 = 0b0000_0100;
pub const EXEC: u8 = 0b0000_1000;
pub const MAP: u8 = 0b0001_0000;
pub const IN_CODE_CACHE: u8 = 0b1000_0000;
pub const ALL: u8 = MAP | INIT | READ | WRITE | EXEC | IN_CODE_CACHE;

pub const READ_WATCH: u8 = 0b0010_0000;
pub const WRITE_WATCH: u8 = 0b0100_0000;

#[inline(always)]
pub fn check(perm: u8, mask: u8) -> MemResult<()> {
    let perm = perm | !mask;
    if perm & ALL != ALL {
        return Err(get_error_kind(perm));
    }
    Ok(())
}

#[inline(always)]
pub fn check_bytes<const N: usize>(mut perm: [u8; N], mask: u8) -> MemResult<()> {
    for (byte, mask) in perm.iter_mut().zip([!mask & ALL; N]) {
        *byte |= mask;
    }
    if perm != [ALL; N] {
        return Err(get_error_kind_bytes(perm));
    }
    Ok(())
}

#[inline(never)]
#[cold]
fn get_error_kind_bytes<const N: usize>(perm: [u8; N]) -> MemError {
    let mut check = ALL;
    for byte in perm {
        check &= byte;
    }
    get_error_kind(check)
}

#[inline(never)]
#[cold]
fn get_error_kind(perm: u8) -> MemError {
    if perm & MAP == 0 {
        MemError::Unmapped
    }
    else if perm & READ == 0 {
        MemError::ReadViolation
    }
    else if perm & WRITE == 0 {
        MemError::WriteViolation
    }
    else if perm & EXEC == 0 {
        MemError::ExecViolation
    }
    else if perm & INIT == 0 {
        MemError::Uninitalized
    }
    else {
        MemError::Unknown
    }
}

#[must_use]
pub fn display(value: u8) -> Permission {
    Permission(value)
}

#[derive(PartialEq, Eq)]
pub struct Permission(u8);

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let perm = self.0;

        let mut values = vec![];
        if perm & MAP == 0 {
            return f.write_str("Unmapped");
        }
        if perm & READ != 0 {
            values.push("R");
        }
        if perm & WRITE != 0 {
            values.push("W");
        }
        if perm & EXEC != 0 {
            values.push("X");
        }
        if perm & INIT != 0 {
            values.push("I");
        }

        if perm & READ_WATCH != 0 {
            values.push("Watch (R)");
        }
        if perm & WRITE_WATCH != 0 {
            values.push("Watch (W)");
        }

        if values.is_empty() {
            return f.write_str("NONE");
        }

        f.write_str(&values.join(" | "))
    }
}

impl std::fmt::Debug for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <Self as std::fmt::Display>::fmt(self, f)
    }
}

#[test]
fn test_check() {
    assert_eq!(check(MAP, MAP), Ok(()));
    assert_eq!(check(NONE, MAP), Err(MemError::Unmapped));

    assert_eq!(check(READ, READ), Ok(()));
    assert_eq!(check(NONE, READ), Err(MemError::ReadViolation));
    assert_eq!(check(NONE, NONE), Ok(()));

    assert_eq!(check(NONE, WRITE), Err(MemError::WriteViolation));
    assert_eq!(check(NONE, EXEC), Err(MemError::ExecViolation));
    assert_eq!(check(NONE, INIT), Err(MemError::Uninitalized));

    assert_eq!(check(READ, READ | INIT), Err(MemError::Uninitalized));
    assert_eq!(check(INIT, READ), Err(MemError::ReadViolation));
    assert_eq!(check(READ | INIT, READ | INIT), Ok(()));
}

#[test]
#[ignore]
fn test_read_write_watch() {
    assert_eq!(check(READ | INIT, READ | INIT | READ_WATCH), Ok(()));
    assert_eq!(check(READ | INIT | READ_WATCH, READ | INIT | READ_WATCH), Err(MemError::ReadWatch));

    assert_eq!(check(WRITE, WRITE | WRITE_WATCH), Ok(()));
    assert_eq!(check(WRITE | WRITE_WATCH, WRITE | WRITE_WATCH), Err(MemError::WriteWatch));
}
