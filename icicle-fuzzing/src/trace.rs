use std::{cell::RefCell, collections::HashSet, path::PathBuf, rc::Rc};

use icicle_vm::cpu::Cpu;

use crate::{initialize_vm_auto, FuzzConfig};

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
        runner.run_vm(&mut vm, &input, u64::MAX)?;
        output.push(CoverageEntry { tag, new: new_cov.borrow().clone() });
        Ok(())
    })?;
    drop(vm);

    let combined_cov = Rc::try_unwrap(total_cov).unwrap().into_inner();
    Ok((combined_cov, output))
}

struct PathTracer {
    /// A list of (block address, icount) pairs tracking all blocks hit by the emulator.
    blocks: Vec<(u64, u64)>,
}

impl PathTracer {
    fn new() -> Self {
        Self { blocks: vec![] }
    }
}

impl icicle_vm::cpu::Hook for PathTracer {
    fn call(&mut self, cpu: &mut icicle_vm::cpu::Cpu, pc: u64) {
        self.blocks.push((pc, cpu.icount()));
    }

    fn as_any(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

pub fn add_path_tracer(vm: &mut icicle_vm::Vm) -> anyhow::Result<PathTracerRef> {
    let hook = vm.cpu.add_hook(Box::new(PathTracer::new()));
    icicle_vm::injector::register_block_hook_injector(vm, 0, u64::MAX, hook);
    Ok(PathTracerRef(hook))
}

pub struct PathTracerRef(pcode::HookId);

impl PathTracerRef {
    pub fn print_last_blocks(&self, vm: &mut icicle_vm::Vm, count: usize) -> String {
        use std::fmt::Write;

        let mut output = String::new();

        for (addr, _) in self.get_last_blocks(vm).iter().rev().take(count) {
            let location = vm
                .env
                .symbolize_addr(&mut vm.cpu, *addr)
                .unwrap_or(icicle_vm::cpu::debug_info::SourceLocation::default());
            writeln!(output, "{addr:#x}: {location}").unwrap();
        }

        output
    }

    pub fn get_last_blocks(&self, vm: &mut icicle_vm::Vm) -> Vec<(u64, u64)> {
        let path_tracer = vm.cpu.get_hook_mut(self.0);
        path_tracer.as_any().downcast_ref::<PathTracer>().unwrap().blocks.clone()
    }

    pub fn clear(&self, vm: &mut icicle_vm::Vm) {
        let path_tracer = vm.cpu.get_hook_mut(self.0);
        path_tracer.as_any().downcast_mut::<PathTracer>().unwrap().blocks.clear();
    }
}
