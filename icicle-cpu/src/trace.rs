use std::{any::Any, cell::UnsafeCell};

use crate::Hook;

#[derive(Default)]
pub struct Trace {
    /// Functions that can be directly called from pcode.
    // @fixme: improve the safety of this.
    pub hooks: UnsafeCell<Vec<Box<dyn Hook>>>,

    /// Storage locations that can be accessed with pcode operations.
    pub storage: Vec<Box<dyn TraceStore>>,
}

impl Trace {
    /// Register a new storage location.
    pub fn register_store(&mut self, store: Box<dyn TraceStore>) -> StoreRef {
        self.storage.push(store);
        StoreRef(self.storage.len() - 1)
    }

    /// Register a new callback function, returning an ID that can be later used to call the
    /// function from pcode.
    pub fn add_hook(&mut self, hook: Box<dyn Hook>) -> pcode::HookId {
        let hooks = self.hooks.get_mut();
        let id = hooks.len().try_into().expect("Exceeded maximum number of hooks");
        hooks.push(hook);
        id
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
    type Output = dyn TraceStore;

    fn index(&self, index: StoreRef) -> &Self::Output {
        &*self.storage[index.0]
    }
}

impl std::ops::IndexMut<StoreRef> for Trace {
    fn index_mut(&mut self, index: StoreRef) -> &mut Self::Output {
        &mut *self.storage[index.0]
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

    fn as_any(&mut self) -> &mut dyn Any;
}

impl TraceStore for (*mut u8, usize) {
    fn data(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.0, self.1) }
    }

    fn data_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.0, self.1) }
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

impl<T: bytemuck::Pod + bytemuck::Zeroable> TraceStore for &'static std::cell::UnsafeCell<T> {
    fn data(&self) -> &[u8] {
        bytemuck::bytes_of(unsafe { self.get().as_ref().unwrap() })
    }

    fn data_mut(&mut self) -> &mut [u8] {
        bytemuck::bytes_of_mut(unsafe { self.get().as_mut().unwrap() })
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

impl TraceStore for Vec<u8> {
    fn data(&self) -> &[u8] {
        self.as_ref()
    }

    fn data_mut(&mut self) -> &mut [u8] {
        self.as_mut()
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

impl TraceStore for Box<[u8]> {
    fn data(&self) -> &[u8] {
        self.as_ref()
    }

    fn data_mut(&mut self) -> &mut [u8] {
        self.as_mut()
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

#[derive(Copy, Clone)]
pub struct StoreRef(usize);

impl StoreRef {
    pub fn get_store_id(&self) -> u16 {
        self.0 as u16 + 1
    }
}
