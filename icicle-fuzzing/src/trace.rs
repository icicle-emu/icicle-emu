use std::{collections::HashSet, path::PathBuf};

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
    let ((mut vm, (total_cov, new_cov)), mut runner) = initialize_vm_auto(config, |vm, config| {
        let total_cov = vm.cpu.trace.register_typed_data(HashSet::new());
        let new_cov = vm.cpu.trace.register_typed_data(HashSet::new());

        let hook = vm.cpu.add_hook(Box::new(move |cpu: &mut Cpu, addr: u64| {
            if cpu.trace[total_cov].insert(addr) {
                cpu.trace[new_cov].insert(addr);
            }
        }));

        let (start, end) = match config.get_instrumentation_range(vm) {
            Some(range) => range,
            None => (0, u64::MAX),
        };
        icicle_vm::injector::register_block_hook_injector(vm, start, end, hook);

        Ok((total_cov, new_cov))
    })?;

    let snapshot = vm.snapshot();

    let mut output = vec![];
    source.visit(|tag, input| {
        vm.cpu.trace[new_cov].clear();
        vm.restore(&snapshot);
        runner.set_input(&mut vm, &input)?;
        vm.run();
        output.push(CoverageEntry { tag, new: vm.cpu.trace[new_cov].clone() });
        Ok(())
    })?;
    let combined_cov = vm.cpu.trace[total_cov].clone();
    drop(vm);

    Ok((combined_cov, output))
}
