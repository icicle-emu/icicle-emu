const REGISTER_SPACE_BYTES: usize = 0x20000;
const MAX_TMPS: usize = 0x200;
const REG_OFFSET: isize = (MAX_TMPS * 16) as isize;

#[cold]
#[inline(never)]
fn invalid_var(var: pcode::VarNode, size: usize) -> ! {
    panic!("read/write to VarNode: {var:?} of size: {size}");
}

pub trait VarSource {
    fn is_valid(&self, var: pcode::VarNode, size: usize) -> bool;
    unsafe fn read_var_unchecked<const N: usize>(&self, var: pcode::VarNode) -> [u8; N];
    unsafe fn write_var_unchecked<const N: usize>(&mut self, var: pcode::VarNode, value: [u8; N]);

    #[inline(always)]
    fn assert_valid(&self, var: pcode::VarNode, size: usize) {
        if !self.is_valid(var, size) {
            invalid_var(var, size);
        }
    }

    #[inline(always)]
    fn write_var<const N: usize>(&mut self, var: pcode::VarNode, val: [u8; N]) {
        self.assert_valid(var, N);
        unsafe { self.write_var_unchecked::<N>(var, val) }
    }

    #[inline(always)]
    fn read_var<const N: usize>(&self, var: pcode::VarNode) -> [u8; N] {
        self.assert_valid(var, N);
        unsafe { self.read_var_unchecked::<N>(var) }
    }
}

pub trait ValueSource {
    fn read_var<R: RegValue>(&self, var: pcode::VarNode) -> R;
    fn read<R: RegValue>(&self, value: pcode::Value) -> R {
        match value {
            pcode::Value::Var(var) => self.read_var(var),
            pcode::Value::Const(x, _) => R::from_u64(x),
        }
    }

    fn write_var<R: RegValue>(&mut self, var: pcode::VarNode, value: R);

    #[inline(always)]
    fn read_dynamic(&self, value: pcode::Value) -> DynamicValue {
        match value.size() {
            1 => DynamicValue::U8(self.read(value)),
            2 => DynamicValue::U16(self.read(value)),
            3 => DynamicValue::U24(self.read(value)),
            4 => DynamicValue::U32(self.read(value)),
            5 => DynamicValue::U40(self.read(value)),
            6 => DynamicValue::U48(self.read(value)),
            7 => DynamicValue::U56(self.read(value)),
            8 => DynamicValue::U64(self.read(value)),
            9 => DynamicValue::U72(self.read(value)),
            10 => DynamicValue::U80(self.read(value)),
            16 => DynamicValue::U128(self.read(value)),
            // For 256 bit values, currently we only support reading the lower 128 bits
            32 => DynamicValue::U128(self.read(value.truncate(16))),
            _ => DynamicValue::U8(0),
        }
    }

    #[inline(always)]
    fn write_trunc(&mut self, var: pcode::VarNode, val: impl Into<DynamicValue>) {
        let val = val.into();
        match var.size {
            1 => self.write_var::<[u8; 1]>(var, val.zxt()),
            2 => self.write_var::<[u8; 2]>(var, val.zxt()),
            3 => self.write_var::<[u8; 3]>(var, val.zxt()),
            4 => self.write_var::<[u8; 4]>(var, val.zxt()),
            5 => self.write_var::<[u8; 5]>(var, val.zxt()),
            6 => self.write_var::<[u8; 6]>(var, val.zxt()),
            7 => self.write_var::<[u8; 7]>(var, val.zxt()),
            8 => self.write_var::<[u8; 8]>(var, val.zxt()),
            9 => self.write_var::<[u8; 9]>(var, val.zxt()),
            10 => self.write_var::<[u8; 10]>(var, val.zxt()),
            16 => self.write_var::<[u8; 16]>(var, val.zxt()),
            // For 256 bit values, currently we only support writing to the lower 128 bits
            32 => self.write_var::<[u8; 16]>(var.truncate(16), val.zxt()),

            _ => (),
        }
    }
}

#[repr(C, align(16))]
pub struct Regs([u8; REGISTER_SPACE_BYTES]);

impl Clone for Regs {
    fn clone(&self) -> Self {
        Self(self.0)
    }

    fn clone_from(&mut self, source: &Self) {
        self.0.copy_from_slice(&source.0);
    }
}

impl Regs {
    pub fn new() -> Regs {
        Regs([0; REGISTER_SPACE_BYTES])
    }

    pub fn fill(&mut self, val: u8) {
        self.0.fill(val);
    }

    #[inline(always)]
    pub fn var_offset(var: pcode::VarNode) -> isize {
        REG_OFFSET + (var.id as isize * 16 + var.offset as isize)
    }

    #[inline]
    pub fn get(&self, var: pcode::VarNode) -> Option<&[u8]> {
        let offset = Self::var_offset(var) as usize;
        self.0.get(offset..offset + var.size as usize)
    }

    #[inline]
    pub fn get_mut(&mut self, var: pcode::VarNode) -> Option<&mut [u8]> {
        let offset = Self::var_offset(var) as usize;
        self.0.get_mut(offset..offset + var.size as usize)
    }

    #[inline(always)]
    pub fn check_bounds(var: pcode::VarNode, size: usize) -> bool {
        var.size as usize == size
            && Self::var_offset(var)
                .checked_add(size as isize)
                .map_or(false, |end| end > 0 && end < REGISTER_SPACE_BYTES as isize)
    }

    #[inline(always)]
    pub unsafe fn read_at<const N: usize>(&self, offset: isize) -> [u8; N] {
        self.0.as_ptr().wrapping_offset(offset).cast::<[u8; N]>().read()
    }

    #[inline(always)]
    pub unsafe fn write_at<const N: usize>(&mut self, offset: isize, value: [u8; N]) {
        self.0.as_mut_ptr().wrapping_offset(offset).cast::<[u8; N]>().write(value);
    }

    pub fn restore_from(&mut self, other: &Regs, valid: usize) {
        let end = REG_OFFSET as usize + valid * 16;
        self.0[..end].copy_from_slice(&other.0[..end]);
    }
}

impl Default for Regs {
    fn default() -> Self {
        Self([0; REGISTER_SPACE_BYTES])
    }
}

impl VarSource for Regs {
    #[inline(always)]
    fn is_valid(&self, var: pcode::VarNode, size: usize) -> bool {
        Self::check_bounds(var, size)
    }

    unsafe fn read_var_unchecked<const N: usize>(&self, var: pcode::VarNode) -> [u8; N] {
        self.read_at(Self::var_offset(var))
    }

    unsafe fn write_var_unchecked<const N: usize>(&mut self, var: pcode::VarNode, value: [u8; N]) {
        self.write_at(Self::var_offset(var), value)
    }
}

impl ValueSource for Regs {
    fn read_var<R: RegValue>(&self, var: pcode::VarNode) -> R {
        R::read(self, var)
    }

    fn write_var<R: RegValue>(&mut self, var: pcode::VarNode, value: R) {
        R::write(self, var, value)
    }
}

#[cfg(target_endian = "little")]
pub(crate) fn resize_zxt<const N: usize, const M: usize>(value: [u8; N]) -> [u8; M] {
    let len = std::cmp::min(N, M);
    let mut bytes = [0; M];
    bytes[..len].copy_from_slice(&value[..len]);
    bytes
}

#[cfg(target_endian = "little")]
pub(crate) fn resize_sxt<const N: usize, const M: usize>(value: [u8; N]) -> [u8; M] {
    assert!(N <= M && M <= 16);
    let bits = N * 8;
    let tmp = u128::from_le_bytes(value.zxt());
    let value = (((tmp << (128 - bits)) as i128) >> (128 - bits)) as u128;
    value.zxt()
}

pub trait RegValue: Sized {
    unsafe fn read_unchecked<R: VarSource>(regs: &R, var: pcode::VarNode) -> Self;
    unsafe fn write_unchecked<R: VarSource>(regs: &mut R, var: pcode::VarNode, val: Self);

    fn from_u64(value: u64) -> Self;
    fn to_dynamic(self) -> DynamicValue;

    #[inline(always)]
    fn read<R: VarSource>(regs: &R, var: pcode::VarNode) -> Self {
        regs.assert_valid(var, std::mem::size_of::<Self>());
        unsafe { RegValue::read_unchecked(regs, var) }
    }

    #[inline(always)]
    fn write<R: VarSource>(regs: &mut R, var: pcode::VarNode, val: Self) {
        regs.assert_valid(var, std::mem::size_of::<Self>());
        unsafe { RegValue::write_unchecked(regs, var, val) }
    }
}

impl<const N: usize> RegValue for [u8; N] {
    #[inline(always)]
    fn from_u64(value: u64) -> Self {
        resize_zxt(value.to_ne_bytes())
    }

    #[inline(always)]
    fn to_dynamic(self) -> DynamicValue {
        DynamicValue::new(resize_zxt(self), N)
    }

    #[inline(always)]
    unsafe fn read_unchecked<R: VarSource>(regs: &R, var: pcode::VarNode) -> Self {
        regs.read_var_unchecked(var)
    }

    #[inline(always)]
    unsafe fn write_unchecked<R: VarSource>(regs: &mut R, var: pcode::VarNode, val: Self) {
        regs.write_var_unchecked(var, val);
    }
}

pub trait ValueBytes<const N: usize>: Sized {
    fn zero() -> Self;
    fn to_ne_bytes(self) -> [u8; N];
    fn from_ne_bytes(bytes: [u8; N]) -> Self;

    fn zxt<T, const M: usize>(self) -> T
    where
        T: ValueBytes<M>,
    {
        T::from_ne_bytes(resize_zxt(self.to_ne_bytes()))
    }

    fn sxt<T, const M: usize>(self) -> T
    where
        T: ValueBytes<M>,
    {
        T::from_ne_bytes(resize_sxt(self.to_ne_bytes()))
    }
}

impl<const N: usize> ValueBytes<N> for [u8; N] {
    #[inline(always)]
    fn zero() -> Self {
        [0; N]
    }

    #[inline(always)]
    fn to_ne_bytes(self) -> [u8; N] {
        self
    }

    #[inline(always)]
    fn from_ne_bytes(bytes: [u8; N]) -> Self {
        bytes
    }
}

macro_rules! impl_reg_value {
    ($type:ty, $size:expr) => {
        impl ValueBytes<$size> for $type {
            #[inline(always)]
            fn zero() -> Self {
                0
            }

            #[inline(always)]
            fn to_ne_bytes(self) -> [u8; $size] {
                <$type>::to_ne_bytes(self)
            }

            #[inline(always)]
            fn from_ne_bytes(bytes: [u8; $size]) -> Self {
                <$type>::from_ne_bytes(bytes)
            }
        }

        impl RegValue for $type {
            #[inline(always)]
            fn from_u64(value: u64) -> Self {
                Self::from_ne_bytes(resize_zxt(value.to_ne_bytes()))
            }

            #[inline(always)]
            fn to_dynamic(self) -> DynamicValue {
                DynamicValue::new(resize_zxt(self.to_ne_bytes()), $size)
            }

            #[inline(always)]
            unsafe fn read_unchecked<R: VarSource>(regs: &R, var: pcode::VarNode) -> Self {
                Self::from_ne_bytes(regs.read_var_unchecked(var))
            }

            #[inline(always)]
            unsafe fn write_unchecked<R: VarSource>(regs: &mut R, var: pcode::VarNode, val: Self) {
                regs.write_var_unchecked(var, val.to_ne_bytes());
            }
        }
    };
}

impl_reg_value!(u8, 1);
impl_reg_value!(i8, 1);
impl_reg_value!(u16, 2);
impl_reg_value!(i16, 2);
impl_reg_value!(u32, 4);
impl_reg_value!(i32, 4);
impl_reg_value!(u64, 8);
impl_reg_value!(i64, 8);
impl_reg_value!(u128, 16);
impl_reg_value!(i128, 16);

#[derive(Debug, Copy, Clone)]
pub enum DynamicValue {
    U8(u8),
    U16(u16),
    U24([u8; 3]),
    U32(u32),
    U40([u8; 5]),
    U48([u8; 6]),
    U56([u8; 7]),
    U64(u64),
    U72([u8; 9]),
    U80([u8; 10]),
    U128(u128),
}

macro_rules! match_dyn_value {
    ($this:ident, $var:ident, $expr:expr) => {
        match $this {
            DynamicValue::U8($var) => $expr,
            DynamicValue::U16($var) => $expr,
            DynamicValue::U24($var) => $expr,
            DynamicValue::U32($var) => $expr,
            DynamicValue::U40($var) => $expr,
            DynamicValue::U48($var) => $expr,
            DynamicValue::U56($var) => $expr,
            DynamicValue::U64($var) => $expr,
            DynamicValue::U72($var) => $expr,
            DynamicValue::U80($var) => $expr,
            DynamicValue::U128($var) => $expr,
        }
    };
}

impl DynamicValue {
    pub fn new(value: [u8; 16], size: usize) -> Self {
        match size {
            1 => DynamicValue::U8(value[0]),
            2 => DynamicValue::U16(u16::from_ne_bytes(resize_zxt(value))),
            3 => DynamicValue::U24(resize_zxt(value)),
            4 => DynamicValue::U32(u32::from_ne_bytes(resize_zxt(value))),
            5 => DynamicValue::U40(resize_zxt(value)),
            6 => DynamicValue::U48(resize_zxt(value)),
            7 => DynamicValue::U56(resize_zxt(value)),
            8 => DynamicValue::U64(u64::from_ne_bytes(resize_zxt(value))),
            9 => DynamicValue::U72(resize_zxt(value)),
            10 => DynamicValue::U80(resize_zxt(value)),
            16 => DynamicValue::U128(u128::from_ne_bytes(resize_zxt(value))),
            _ => panic!("invalid dynamic value size"),
        }
    }

    #[inline]
    pub fn zxt<T, const M: usize>(self) -> T
    where
        T: ValueBytes<M>,
    {
        match_dyn_value!(self, x, x.zxt())
    }

    #[inline]
    pub fn sxt<T, const M: usize>(self) -> T
    where
        T: ValueBytes<M>,
    {
        match_dyn_value!(self, x, x.sxt())
    }
}

macro_rules! impl_dynamic_value_primitive_try_into {
    (($ty:ty, $tag:ident)) => {
        impl From<$ty> for DynamicValue {
            #[inline(always)]
            fn from(value: $ty) -> Self {
                DynamicValue::$tag(value)
            }
        }

        impl TryInto<$ty> for DynamicValue {
            type Error = ();

            #[inline(always)]
            fn try_into(self) -> Result<$ty, Self::Error> {
                match self {
                    DynamicValue::$tag(x) => Ok(x),
                    _ => Err(()),
                }
            }
        }
    };

    (($type:ty, $tag:ident), $(($types:ty, $tags:ident)),+) => {
        impl_dynamic_value_primitive_try_into!(($type, $tag));
        impl_dynamic_value_primitive_try_into!($(($types, $tags)),+);
    };
}

impl_dynamic_value_primitive_try_into!((u8, U8), (u16, U16), (u32, U32), (u64, U64), (u128, U128));

#[cfg(test)]
mod test {
    use super::{Regs, ValueSource};

    #[test]
    fn test_regs() {
        let mut regs: Box<Regs> = Box::default();

        regs.write_var(pcode::VarNode::new(0, 1), 0x01_u8);
        regs.write_var(pcode::VarNode::new(1, 1), 0x02_u8);

        assert_eq!(regs.read_var::<u8>(pcode::VarNode::new(0, 1)), 0x01_u8);
        assert_eq!(regs.read_var::<u8>(pcode::VarNode::new(1, 1)), 0x02_u8);

        regs.write_var(pcode::VarNode::new(0, 2), 0x1211_u16);
        regs.write_var(pcode::VarNode::new(1, 2), 0x1413_u16);

        assert_eq!(regs.read_var::<u16>(pcode::VarNode::new(0, 2)), 0x1211_u16);
        assert_eq!(regs.read_var::<u16>(pcode::VarNode::new(1, 2)), 0x1413_u16);
    }
}
