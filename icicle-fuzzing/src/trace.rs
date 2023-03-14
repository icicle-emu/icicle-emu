use std::{cell::RefCell, collections::HashSet, path::PathBuf, rc::Rc};

use icicle_vm::cpu::Cpu;

use crate::{initialize_vm_auto, FuzzConfig};

pub use icicle_vm::injector::{add_path_tracer, PathTracerRef};

pub struct CoverageEntry<T> {
    /// The the tag associated with the input.
    pub tag: T,

    /// The new blocks that were covered by this input.
    pub new: HashSet<u64>,
}

pub trait InputSource {
    type Tag;
    fn visit(
        &mut self,
        handler: impl FnMut(Self::Tag, Vec<u8>) -> anyhow::Result<()>,
    ) -> anyhow::Result<()>;
}

pub trait IntoInputSource {
    type Tag;
    type Source: InputSource<Tag = Self::Tag>;
    fn into_input_source(self) -> Self::Source;
}

pub struct DirInputSource(std::path::PathBuf);

impl InputSource for DirInputSource {
    type Tag = PathBuf;

    fn visit(
        &mut self,
        handler: impl FnMut(Self::Tag, Vec<u8>) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        crate::utils::input_visitor(&self.0, handler)
    }
}

impl IntoInputSource for std::path::PathBuf {
    type Tag = std::path::PathBuf;
    type Source = DirInputSource;

    fn into_input_source(self) -> Self::Source {
        DirInputSource(self)
    }
}

pub fn resolve_block_coverage<I>(
    config: &mut FuzzConfig,
    source: I,
) -> anyhow::Result<(HashSet<u64>, Vec<CoverageEntry<I::Tag>>)>
where
    I: IntoInputSource,
{
    resolve_block_coverage_impl(config, source.into_input_source())
}

fn resolve_block_coverage_impl<I>(
    config: &mut FuzzConfig,
    mut source: I,
) -> anyhow::Result<(HashSet<u64>, Vec<CoverageEntry<I::Tag>>)>
where
    I: InputSource,
{
    let total_cov = Rc::new(RefCell::new(HashSet::new()));
    let new_cov = Rc::new(RefCell::new(HashSet::new()));

    let ((mut vm, _), mut runner) = initialize_vm_auto(config, |vm, config| {
        let combined = total_cov.clone();
        let new = new_cov.clone();

        let hook = vm.cpu.add_hook(Box::new(move |_: &mut Cpu, addr: u64| {
            if combined.borrow_mut().insert(addr) {
                new.borrow_mut().insert(addr);
            }
        }));

        let (start, end) = match config.get_instrumentation_range(vm) {
            Some(range) => range,
            None => (0, u64::MAX),
        };
        icicle_vm::injector::register_block_hook_injector(vm, start, end, hook);

        Ok(())
    })?;

    let snapshot = vm.snapshot();

    let mut output = vec![];
    source.visit(|tag, input| {
        new_cov.borrow_mut().clear();
        vm.restore(&snapshot);
        runner.set_input(&mut vm, &input)?;
        vm.run();
        output.push(CoverageEntry { tag, new: new_cov.borrow().clone() });
        Ok(())
    })?;
    drop(vm);

    let combined_cov = Rc::try_unwrap(total_cov).unwrap().into_inner();
    Ok((combined_cov, output))
}
