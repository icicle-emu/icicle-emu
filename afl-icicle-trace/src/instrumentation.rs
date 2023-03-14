use icicle_fuzzing::{
    cmplog::CmpMap,
    coverage::{AFLHitCountsBuilder, BlockCoverageBuilder},
    CoverageMode,
};
use icicle_vm::cpu::lifter::Block;

use crate::{is_cmplog_server, shared_mem, FuzzConfig};

/// Keeps track of the instrumentation metadata associated wit the current fuzzing session.
pub struct Instrumentation {
    cov: (*mut u8, u32),
    cmplog_map: Option<&'static std::cell::UnsafeCell<CmpMap>>,
    path_tracer: Option<icicle_fuzzing::trace::PathTracerRef>,
}

impl Instrumentation {
    pub fn clear(&mut self, vm: &mut icicle_vm::Vm) {
        // Reset coverage to default state, note we set a single value in the coverage map, because
        // AFL++ checks the map to determine whether the backend is working.
        let cov_slice = unsafe { std::slice::from_raw_parts_mut(self.cov.0, self.cov.1 as usize) };
        cov_slice.fill(0);
        cov_slice[0] = 1;

        if let Some(_) = self.cmplog_map {
            // AFL++ takes care of clearing the cmplog_map after each input
        }

        if let Some(tracer) = self.path_tracer.as_ref() {
            tracer.clear(vm);
        }
    }

    pub fn save_cmplog_map(&mut self, path: &std::path::Path) -> std::io::Result<()> {
        if let Some(map) = self.cmplog_map {
            unsafe { map.get().as_ref().unwrap() }.save(path)?;
        }
        Ok(())
    }
}

pub fn instrument_vm(
    vm: &mut icicle_vm::Vm,
    config: &FuzzConfig,
) -> anyhow::Result<Instrumentation> {
    // Obtain references to the shared memory regions created by AFL.
    //
    // Safety: we "trust" that the parent invoked this program correctly and both shared memory
    // regions are set up.
    let (afl_area_ptr, afl_map_size) = unsafe { shared_mem::afl_area()? };
    let cmplog_map =
        if is_cmplog_server() { Some(unsafe { shared_mem::cmplog_map()? }) } else { None };

    let (start_addr, end_addr) = config.get_instrumentation_range(vm).unwrap_or((0, u64::MAX));

    let filter = move |block: &Block| start_addr <= block.start && block.start <= end_addr;
    let cov_map = match config.coverage_mode {
        CoverageMode::Blocks => BlockCoverageBuilder::new()
            .filter(filter)
            .enable_context(config.context_bits != 0)
            .finish(vm, afl_area_ptr, afl_map_size as u32),
        CoverageMode::BlockCounts => anyhow::bail!("Block counts not implemented"),
        CoverageMode::Edges => anyhow::bail!("Edge-only coverage not implemented"),
        CoverageMode::EdgeCounts => AFLHitCountsBuilder::new()
            .filter(filter)
            .with_context(config.context_bits)
            .finish(vm, afl_area_ptr, afl_map_size as u32),
    };

    if let Some(map) = cmplog_map {
        icicle_fuzzing::cmplog::CmpLogBuilder::new()
            .filter(move |block| start_addr <= block.start && block.start <= end_addr)
            .instrument_calls(!config.no_cmplog_return)
            .finish(vm, map);
    }

    if let Some(level) = config.compcov_level {
        icicle_fuzzing::compcov::CompCovBuilder::new()
            .filter(move |block| start_addr <= block.start && block.start <= end_addr)
            .level(level)
            .finish(vm, cov_map);
    }

    let mut tracer = None;
    if config.track_path {
        tracer = Some(icicle_fuzzing::trace::add_path_tracer(vm)?);
    }

    Ok(Instrumentation {
        cov: (afl_area_ptr, afl_map_size as u32),
        cmplog_map,
        path_tracer: tracer,
    })
}

#[allow(dead_code)]
pub(crate) fn no_instrumentation(
    _vm: &mut icicle_vm::Vm,
    _config: &FuzzConfig,
) -> anyhow::Result<()> {
    Ok(())
}
