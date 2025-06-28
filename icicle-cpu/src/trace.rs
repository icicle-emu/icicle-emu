use std::{any::Any, cell::UnsafeCell};

use crate::Cpu;

pub const MAX_TRACER_MEM: usize = 64;

#[derive(Default)]
pub struct Trace {
    /// Functions that can be directly called from pcode.
    ///
    /// Safety: This field must not be accessed from within a hook.
    // @fixme: prevent misuses.
    pub(crate) hooks: UnsafeCell<Vec<InstHook>>,

    /// Storage locations that can be accessed with pcode operations.
    pub(crate) storage: Vec<Box<dyn TraceStoreAny>>,

    /// Typed data stored in emulator.
    pub(crate) data: Vec<Box<dyn Any>>,
}

impl Trace {
    /// Register a new storage location.
    pub fn register_store(&mut self, store: impl TraceStore + 'static) -> StoreRef {
        self.storage.push(Box::new(store));
        StoreRef(self.storage.len() - 1)
    }

    /// Register a new callback function, returning an ID that can be later used to call the
    /// function from pcode.
    pub fn add_hook(&mut self, hook: InstHook) -> pcode::HookId {
        let hooks = self.hooks.get_mut();
        let id = hooks.len().try_into().expect("Exceeded maximum number of hooks");
        hooks.push(hook);
        id
    }

    /// Register arbitary data inside the emulator, returning a handle used to access the data.
    pub fn register_typed_data<T: 'static>(&mut self, data: T) -> DataHandle<T> {
        self.data.push(Box::new(data));
        DataHandle { idx: self.data.len() - 1, type_: std::marker::PhantomData::default() }
    }

    /// Returns an iterator to the pointers to the final address of each [TraceStore].
    ///
    /// Safety: The lifetime of each pointer in the return array is tied to the lifetime of self.
    ///
    /// @fixme?: Consider also returning the lengths of each storage location (currently the JIT
    /// doesn't check that writes to the storage locations are in bounds).
    ///
    /// @fixme?: Consider using `Pin` to improve safety.
    #[inline]
    pub fn storage_ptr(&mut self) -> impl Iterator<Item = *mut u8> + '_ {
        self.storage.iter_mut().map(|x| x.data_mut().as_mut_ptr())
    }
}

impl std::ops::Index<StoreRef> for Trace {
    type Output = dyn TraceStoreAny;

    #[inline]
    fn index(&self, index: StoreRef) -> &Self::Output {
        &*self.storage[index.0]
    }
}

impl std::ops::IndexMut<StoreRef> for Trace {
    #[inline]
    fn index_mut(&mut self, index: StoreRef) -> &mut Self::Output {
        &mut *self.storage[index.0]
    }
}

impl<T: 'static> std::ops::Index<DataHandle<T>> for Trace {
    type Output = T;

    #[inline]
    fn index(&self, handle: DataHandle<T>) -> &Self::Output {
        let data_ref = self.data[handle.idx].as_ref().downcast_ref();
        data_ref.unwrap()
    }
}

impl<T: 'static> std::ops::IndexMut<DataHandle<T>> for Trace {
    #[inline]
    fn index_mut(&mut self, handle: DataHandle<T>) -> &mut Self::Output {
        let data_mut = self.data[handle.idx].as_mut().downcast_mut();
        data_mut.unwrap()
    }
}

pub trait TraceStore {
    fn data(&self) -> &[u8];

    fn data_mut(&mut self) -> &mut [u8];

    fn read(&mut self, offset: usize, len: usize) -> Option<u64> {
        let slice = self.data_mut().get(offset..offset + len)?;
        let mut value = [0; 8];
        value[..len].copy_from_slice(slice);
        Some(u64::from_le_bytes(value))
    }

    fn write(&mut self, offset: usize, value: u64, len: usize) -> Option<()> {
        let slice = self.data_mut().get_mut(offset..offset + len)?;
        slice.copy_from_slice(&value.to_le_bytes()[..len]);
        Some(())
    }
}

pub trait TraceStoreAny: TraceStore {
    fn as_any(&self) -> &dyn Any;
    fn as_mut_any(&mut self) -> &mut dyn Any;
}

impl<T: TraceStore + 'static> TraceStoreAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn Any {
        self
    }
}

impl TraceStore for (*mut u8, usize) {
    fn data(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.0, self.1) }
    }

    fn data_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.0, self.1) }
    }
}

impl<T: bytemuck::Pod + bytemuck::Zeroable> TraceStore for &'static std::cell::UnsafeCell<T> {
    fn data(&self) -> &[u8] {
        bytemuck::bytes_of(unsafe { self.get().as_ref().unwrap() })
    }

    fn data_mut(&mut self) -> &mut [u8] {
        bytemuck::bytes_of_mut(unsafe { self.get().as_mut().unwrap() })
    }
}

impl TraceStore for Vec<u8> {
    fn data(&self) -> &[u8] {
        self.as_ref()
    }

    fn data_mut(&mut self) -> &mut [u8] {
        self.as_mut()
    }
}

impl TraceStore for Vec<u64> {
    fn data(&self) -> &[u8] {
        bytemuck::cast_slice(self.as_ref())
    }

    fn data_mut(&mut self) -> &mut [u8] {
        bytemuck::cast_slice_mut(self.as_mut())
    }
}

impl TraceStore for Box<[u8]> {
    fn data(&self) -> &[u8] {
        self.as_ref()
    }

    fn data_mut(&mut self) -> &mut [u8] {
        self.as_mut()
    }
}

#[derive(Copy, Clone)]
pub struct StoreRef(usize);

impl StoreRef {
    #[inline]
    pub fn get_store_id(&self) -> u16 {
        self.0 as u16 + pcode::RESERVED_SPACE_END
    }
}

pub struct DataHandle<T> {
    idx: usize,
    type_: std::marker::PhantomData<fn(&T)>,
}

impl<T> Copy for DataHandle<T> {}

impl<T> Clone for DataHandle<T> {
    fn clone(&self) -> Self {
        Self { idx: self.idx.clone(), type_: self.type_.clone() }
    }
}

pub const MAX_HOOKS: usize = 64;

#[repr(C)]
pub struct HookData {
    pub fn_ptr: HookTrampoline,
    pub data_ptr: *mut (),
}

impl HookData {
    pub const fn null() -> Self {
        extern "C" fn null_hook(_: *mut (), _: *mut Cpu, _: u64) {}
        Self { fn_ptr: null_hook, data_ptr: std::ptr::null_mut() }
    }
}

pub type HookTrampoline = extern "C" fn(*mut (), *mut Cpu, u64);

pub struct InstHook {
    func: HookTrampoline,
    data: *mut (),
    drop: fn(*mut ()),
    type_id: std::any::TypeId,
}

impl Drop for InstHook {
    fn drop(&mut self) {
        if !self.data.is_null() {
            (self.drop)(self.data);
            self.data = std::ptr::null_mut();
        }
    }
}

impl InstHook {
    pub fn new<H: HookHandler>(data: H) -> Self {
        Self {
            func: Self::trampoline::<H>,
            data: Box::into_raw(Box::new(data)).cast(),
            drop: Self::drop_data::<H>,
            type_id: std::any::TypeId::of::<H>(),
        }
    }

    #[inline]
    pub fn call(&mut self, cpu: &mut Cpu, pc: u64) {
        (self.func)(self.data, cpu, pc)
    }

    #[inline]
    pub fn get_ptr(&self) -> (HookTrampoline, *mut ()) {
        (self.func, self.data)
    }

    #[inline]
    pub fn data_mut<T: 'static>(&mut self) -> Option<&mut T> {
        if self.type_id == std::any::TypeId::of::<T>() {
            unsafe { self.data.cast::<T>().as_mut() }
        }
        else {
            None
        }
    }

    fn drop_data<H: HookHandler>(data: *mut ()) {
        unsafe {
            _ = Box::from_raw(data.cast::<H>());
        }
    }

    #[inline(always)]
    extern "C" fn trampoline<H: HookHandler>(data: *mut (), cpu: *mut Cpu, addr: u64) {
        unsafe { H::call(&mut *data.cast::<H>(), &mut *cpu, addr) }
    }
}

pub trait HookHandler: Sized + 'static {
    fn call(data: &mut Self, cpu: &mut Cpu, addr: u64);
}

impl<F> HookHandler for F
where
    F: FnMut(&mut Cpu, u64) + 'static,
{
    #[inline(always)]
    fn call(func: &mut Self, cpu: &mut Cpu, addr: u64) {
        func(cpu, addr)
    }
}

impl<H: HookHandler> From<H> for InstHook {
    fn from(callback: H) -> Self {
        InstHook::new::<H>(callback)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn call_simple() {
        let data = std::rc::Rc::new(std::cell::Cell::new(false));
        {
            let data = data.clone();
            let mut hook = InstHook::new(move |_: &mut crate::Cpu, _addr: u64| data.set(true));
            hook.call(&mut crate::Cpu::new_boxed(crate::Arch::none()), 0);
        }
        assert!(data.get())
    }

    #[test]
    fn get_data() {
        struct HookData(bool);

        impl HookHandler for HookData {
            fn call(data: &mut Self, _: &mut Cpu, _: u64) {
                data.0 = true;
            }
        }

        let mut hook = InstHook::new(HookData(false));
        hook.call(&mut crate::Cpu::new_boxed(crate::Arch::none()), 0);

        assert!(hook.data_mut::<HookData>().unwrap().0)
    }
}
