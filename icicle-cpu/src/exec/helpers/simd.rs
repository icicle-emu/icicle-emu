use super::*;

pub fn ones(bits: u32) -> u128 {
    if bits == 128 { u128::MAX } else { (1u128 << bits) - 1 }
}

pub struct Simd {
    pub value: u128,
    pub size: u8,
    pub lane_size: u8,
}

impl Simd {
    pub fn read(cpu: &mut Cpu, value: Value, esize: u8) -> Result<Self> {
        let size = value.size();
        if ![1, 2, 4, 8].contains(&esize) || size % esize != 0 || size > 128 {
            return Err(ExceptionCode::InvalidOpSize);
        }
        let value: u128 = cpu.read_dynamic(value).zxt();
        Ok(Self::new(value, size, esize))
    }

    pub fn new(value: u128, size: u8, lane_size: u8) -> Self {
        Self { value, size, lane_size }
    }

    pub fn broadcast(value: u128, size: u8, lane_size: u8) -> Self {
        let mut out = Self::new(0, size, lane_size);
        for index in 0..out.n_lanes() {
            out.set_lane(index, value);
        }
        out
    }

    pub fn n_lanes(&self) -> u8 {
        self.size / self.lane_size
    }

    pub fn set_lane(&mut self, index: u8, value: u128) {
        let shift = index * (self.lane_size * 8);
        let mask = ones(self.lane_size as u32 * 8) << shift;
        self.value = (self.value & !mask) | (((value as u128) << shift) & mask);
    }

    pub fn get_lane(&self, index: u8) -> u128 {
        let shift = index * (self.lane_size * 8);
        let mask = ones(self.lane_size as u32 * 8) << shift;
        ((self.value & mask) >> shift) as u128
    }

    pub fn apply(&self, mut f: impl FnMut(u128) -> u128) -> Simd {
        let mut out = Simd::new(0, self.size, self.lane_size);
        for index in 0..self.n_lanes() {
            out.set_lane(index, f(self.get_lane(index)));
        }
        out
    }

    pub fn resize_lanes(&self, new_lane_size: u8) -> Self {
        assert!([1, 2, 4, 8, 16].contains(&new_lane_size));

        let mut out = Simd::new(0, new_lane_size * self.n_lanes(), new_lane_size);
        for index in 0..self.n_lanes() {
            out.set_lane(index, self.get_lane(index));
        }
        out
    }

    pub fn resize_sxt(&self, new_lane_size: u8) -> Self {
        assert!([1, 2, 4, 8, 16].contains(&new_lane_size));

        let mut out = Simd::new(0, new_lane_size * self.n_lanes(), new_lane_size);
        for index in 0..self.n_lanes() {
            out.set_lane(index, pcode::sxt128(self.get_lane(index), 8 * self.lane_size as u64));
        }
        out
    }

    pub fn concat(&self, y: &Simd) -> Result<Simd> {
        if self.size + y.size > 16 {
            return Err(ExceptionCode::InvalidOpSize);
        }
        Ok(Simd::new(self.get() | (y.get() << self.size), self.size + y.size, self.lane_size))
    }

    pub fn reduce(&self, op: impl FnMut(u128, u128) -> u128) -> u128 {
        (0..self.n_lanes()).map(|i| self.get_lane(i)).reduce(op).unwrap()
    }

    pub fn reduce_signed(&self, op: impl FnMut(i128, i128) -> i128) -> i128 {
        (0..self.n_lanes())
            .map(|i| pcode::sxt128(self.get_lane(i), 8 * self.lane_size as u64) as i128)
            .reduce(op)
            .unwrap()
    }

    pub fn get(&self) -> u128 {
        self.value & ones(self.size as u32 * 8)
    }
}

pub fn check_size_match(a: &Simd, b: &Simd) -> Result {
    if a.size != b.size {
        return Err(ExceptionCode::InvalidOpSize);
    }
    Ok(())
}

pub fn packed(a: &Simd, b: &Simd, mut f: impl FnMut(u128, u128) -> u128) -> Result<Simd> {
    check_size_match(a, b)?;
    let mut out = Simd::new(0, a.size, a.lane_size);
    for lane in 0..a.n_lanes() {
        let a = a.get_lane(lane);
        let b = b.get_lane(lane);
        out.set_lane(lane, f(a, b));
    }
    Ok(out)
}

pub fn packed_signed(
    a: &Simd,
    b: &Simd,
    mut f: impl FnMut(i128, i128) -> i128,
) -> Result<Simd, ExceptionCode> {
    packed(a, b, |x, y| {
        let x = pcode::sxt128(x, 8 * a.lane_size as u64);
        let y = pcode::sxt128(y, 8 * a.lane_size as u64);
        f(x as i128, y as i128) as u128
    })
}

pub fn pairwise(x: &Simd, mut f: impl FnMut(u64, u64) -> u64) -> Result<Simd> {
    let mut out = Simd::new(0, x.size / 2, x.lane_size);
    for lane in (0..x.n_lanes()).step_by(2) {
        let a = x.get_lane(lane) as u64;
        let b = x.get_lane(lane + 1) as u64;
        out.set_lane(lane / 2, f(a as u64, b as u64) as u128);
    }
    Ok(out)
}

pub fn simd_set(cpu: &mut Cpu, dst: VarNode, value: Simd) -> Result {
    if dst.size != value.size as u8 {
        return Err(ExceptionCode::InvalidOpSize);
    }
    cpu.write_trunc(dst, value.value);
    Ok(())
}

/// Compares each lane of two vectors, setting every bit of the lane if the comparison is true.
pub fn vector_compare(
    cpu: &mut Cpu,
    dst: VarNode,
    args: [Value; 2],
    esize: u8,
    is_unsigned: bool,
    cmp: fn(i128, i128) -> bool,
) -> Result {
    let a = Simd::read(cpu, args[0], esize)?;
    let b = Simd::read(cpu, args[1], esize)?;
    let result = match is_unsigned {
        true => packed(&a, &b, |x, y| if cmp(x as i128, y as i128) { u128::MAX } else { 0 })?,
        false => packed_signed(&a, &b, |x, y| if cmp(x, y) { -1 } else { 0 })?,
    };
    simd_set(cpu, dst, result)
}
