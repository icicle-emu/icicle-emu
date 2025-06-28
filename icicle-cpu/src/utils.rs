pub fn align_up(value: u64, alignment: u64) -> u64 {
    assert_eq!(alignment.count_ones(), 1, "Alignment must be a non-zero power of 2");
    let mask = alignment.wrapping_sub(1);
    value + ((alignment - (value & mask)) & mask)
}

pub fn align_down(value: u64, alignment: u64) -> u64 {
    assert_eq!(alignment.count_ones(), 1, "Alignment must be a non-zero power of 2");
    let mask = !alignment.wrapping_sub(1);
    value & mask
}

#[derive(Copy, Clone)]
pub struct XorShiftRng {
    pub seed: u64,
}

impl XorShiftRng {
    pub fn new(seed: u64) -> Self {
        Self { seed }
    }

    pub fn next(&mut self) -> u64 {
        let mut x = self.seed;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.seed = x;
        x
    }

    pub fn fill_bytes(&mut self, mut buf: &mut [u8]) {
        while !buf.is_empty() {
            for (buf, value) in buf.iter_mut().zip(self.next().to_le_bytes()) {
                *buf = value;
            }
            let len = usize::min(buf.len(), std::mem::size_of::<u64>());
            buf = &mut buf[len..];
        }
    }
}

pub struct UdpWriter {
    socket: Option<std::net::UdpSocket>,
}

impl UdpWriter {
    pub fn new(addr: &str) -> Self {
        Self::try_connect(addr).unwrap_or(Self { socket: None })
    }

    fn try_connect(addr: &str) -> Option<Self> {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").ok()?;
        socket.connect(addr).ok()?;
        Some(Self { socket: Some(socket) })
    }
}

impl std::io::Write for UdpWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(socket) = self.socket.as_mut() {
            socket.send(&buf[..buf.len().min(512)])
        }
        else {
            Ok(buf.len())
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Formats bytes as a byte array
pub fn format_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write;

    if bytes.is_empty() {
        return String::from("[]");
    }

    let mut out = String::with_capacity(3 * bytes.len());
    out.push('[');
    for byte in bytes.iter().take(bytes.len() - 1) {
        out.write_fmt(format_args!("{:02x} ", byte)).unwrap();
    }

    out.write_fmt(format_args!("{:02x}", bytes.last().unwrap())).unwrap();
    out.push(']');

    out
}

/// Formats a byte array as a string of hex characters
pub fn hex(bytes: &[u8]) -> String {
    const LOOKUP_4BITS: &[u8] = b"0123456789abcdef";

    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(LOOKUP_4BITS[((byte >> 4) & 0xF) as usize] as char);
        out.push(LOOKUP_4BITS[(byte & 0xF) as usize] as char);
    }
    out
}

/// Utility function for converting a hex string to a byte array. Returns `None` if the input string
/// is not a valid hex string.
pub fn bytes_from_hex(hex: &str) -> Option<Vec<u8>> {
    let match_ascii = |ascii: u8| -> Option<u8> {
        Some(match ascii {
            b'0' => 0x0,
            b'1' => 0x1,
            b'2' => 0x2,
            b'3' => 0x3,
            b'4' => 0x4,
            b'5' => 0x5,
            b'6' => 0x6,
            b'7' => 0x7,
            b'8' => 0x8,
            b'9' => 0x9,
            b'a' | b'A' => 0xa,
            b'b' | b'B' => 0xb,
            b'c' | b'C' => 0xc,
            b'd' | b'D' => 0xd,
            b'e' | b'E' => 0xe,
            b'f' | b'F' => 0xf,
            _ => return None,
        })
    };

    if hex.len() % 2 != 0 {
        return None;
    }

    let mut output = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks_exact(2) {
        output.push((match_ascii(pair[0])? << 4) | match_ascii(pair[1])?);
    }

    Some(output)
}

/// Reads a LE encoded u64 from a slice of bytes, zero-extending if the slice is too short.
pub fn get_u64(value: &[u8]) -> u64 {
    match *value {
        [x0] => u8::from_le_bytes([x0]) as u64,
        [x0, x1] => u16::from_le_bytes([x0, x1]) as u64,
        [x0, x1, x2, x3] => u32::from_le_bytes([x0, x1, x2, x3]) as u64,
        [x0, x1, x2, x3, x4, x5, x6, x7] => u64::from_le_bytes([x0, x1, x2, x3, x4, x5, x6, x7]),
        _ => 0,
    }
}

/// Parse a u64 with either no prefix (decimal), '0x' prefix (hex), or '0b' (binary)
pub fn parse_u64_with_prefix(value: &str) -> Option<u64> {
    if value.len() < 2 {
        return value.parse().ok();
    }

    let (value, radix) = match &value[0..2] {
        "0x" => (&value[2..], 16),
        "0b" => (&value[2..], 2),
        _ => (value, 10),
    };

    u64::from_str_radix(value, radix).ok()
}

pub struct BasicInstructionSource {
    pub arch: crate::Arch,
    base_addr: u64,
    mem: Vec<u8>,
}

impl BasicInstructionSource {
    pub fn new(sleigh: sleigh_runtime::SleighData) -> Self {
        let arch = crate::Arch {
            triple: target_lexicon::Triple::unknown(),
            reg_pc: pcode::VarNode::new(0, 8),
            reg_next_pc: pcode::VarNode::NONE,
            reg_sp: pcode::VarNode::NONE,
            reg_isa_mode: None,
            isa_mode_context: vec![],
            reg_init: vec![],
            on_boot: crate::cpu::generic_on_boot,
            calling_cov: crate::cpu::CallCov::default(),
            temporaries: vec![],
            sleigh,
        };
        Self { arch, base_addr: 0, mem: vec![] }
    }

    pub fn set_inst(&mut self, addr: u64, bytes: &[u8]) {
        self.mem.clear();
        self.mem.extend_from_slice(bytes);
        self.base_addr = addr;
    }

    fn get_mem_region(&self, vaddr: u64, size: usize) -> Option<&[u8]> {
        let start = vaddr.checked_sub(self.base_addr)? as usize;
        let buf = self.mem.get(start..)?;
        Some(&buf[..size.min(buf.len())])
    }
}

impl crate::lifter::InstructionSource for BasicInstructionSource {
    fn arch(&self) -> &crate::Arch {
        &self.arch
    }

    fn read_bytes(&mut self, vaddr: u64, buf: &mut [u8]) {
        buf.fill(0);
        match self.get_mem_region(vaddr, buf.len()) {
            Some(data) => buf[..data.len()].copy_from_slice(data),
            None => buf.fill(0),
        }
    }

    fn ensure_exec(&mut self, vaddr: u64, size: usize) -> bool {
        self.get_mem_region(vaddr, size).map_or(false, |x| x.len() == size)
    }
}
