mod debug;
pub mod runtime;
mod translate;

use std::collections::HashMap;

use codegen::ir::Endianness;
use cranelift::{codegen::Context as CodeContext, prelude::*};
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{FuncId, Linkage, Module, ModuleResult};

use icicle_cpu::{lifter::Block as IcicleBlock, Cpu, HookTrampoline};

use crate::translate::TranslatorCtx;

#[repr(C)]
pub struct VmCtx {
    pub tlb_ptr: *mut icicle_cpu::mem::tlb::TranslationCache,
    pub tracer_mem: [*mut u8; MAX_TRACER_MEM],
    pub hooks: [HookData; MAX_HOOKS],
}

impl VmCtx {
    pub fn new() -> Self {
        const NULL_HOOK: HookData = HookData::null();

        Self {
            tlb_ptr: std::ptr::null_mut(),
            tracer_mem: [std::ptr::null_mut(); MAX_TRACER_MEM],
            hooks: [NULL_HOOK; MAX_HOOKS],
        }
    }
}

pub type JitFunction = unsafe extern "C" fn(*mut Cpu, &mut VmCtx, u64) -> u64;

pub(crate) struct MemHandler<T> {
    pub load8: T,
    pub load16: T,
    pub load32: T,
    pub load64: T,
    pub load128: T,

    pub store8: T,
    pub store16: T,
    pub store32: T,
    pub store64: T,
    pub store128: T,
}

pub(crate) struct RuntimeFunctions {
    pub mmu: MemHandler<FuncId>,

    pub push_shadow_stack: FuncId,
    pub pop_shadow_stack: FuncId,

    pub run_interpreter: FuncId,
    pub hook_signature: Signature,
}

const MAX_TRACER_MEM: usize = 64;
type TracerMemEntry = *mut u8;

const MAX_HOOKS: usize = 64;

extern "C" fn null_hook(_: *mut (), _: *mut Cpu, _: u64) {}

#[repr(C)]
pub struct HookData {
    pub fn_ptr: HookTrampoline,
    pub data_ptr: *mut (),
}

impl HookData {
    pub const fn null() -> Self {
        Self { fn_ptr: null_hook, data_ptr: std::ptr::null_mut() }
    }
}

pub struct CompilationTarget<'a> {
    pub blocks: &'a [IcicleBlock],
    pub targets: &'a [usize],
}

impl<'a> CompilationTarget<'a> {
    pub fn new(blocks: &'a [IcicleBlock], targets: &'a [usize]) -> Self {
        Self { blocks, targets }
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (usize, &IcicleBlock)> {
        self.targets.iter().copied().map(|id| (id, &self.blocks[id]))
    }

    pub(crate) fn entry_points(&self) -> impl Iterator<Item = u64> + '_ {
        self.targets.iter().copied().filter_map(|id| self.blocks[id].entry)
    }
}

const FAST_LOOKUP_TABLE_SIZE: usize = 0x10000;

pub struct JIT {
    /// The endianness of the guest architecture
    endianness: Endianness,

    /// The function builder context, which is reused across multiple FunctionBuilder instances.
    builder_ctx: FunctionBuilderContext,

    /// Cranelift codegen context.
    code_ctx: CodeContext,

    /// Context for translator.
    translator_ctx: TranslatorCtx,

    /// The module, with the jit backend, which manages the JIT'd functions.
    module: JITModule,

    /// The runtime functions available to the JIT.
    functions: RuntimeFunctions,

    /// (debugging) Storage for writting the current IL to after compilation.
    /// If `None`, no IL will be written.
    pub il_dump: Option<String>,

    /// Number of times we hit the fast lookup table.
    pub jit_hit: u64,

    /// Number of times we missed the fast lookup table.
    pub jit_miss: u64,

    /// Cached JIT functions indexed by entrypoint.
    pub entry_points: HashMap<u64, JitFunction>,

    /// The JIT functions for each address that are currently active.
    active: Box<[(u64, JitFunction); FAST_LOOKUP_TABLE_SIZE]>,

    /// Keeps track of the guest entry points of all code compiled by the JIT.
    compiled: Vec<Vec<u64>>,

    /// A mapping from `block_id` to the compilation group it is a part of.
    block_mapping: HashMap<usize, usize>,

    /// Number of dead compilation units.
    pub dead: usize,

    /// A list of declared functions (used for debugging).
    declared_functions: Vec<(FuncId, u64)>,
}

impl JIT {
    pub fn new(cpu: &icicle_cpu::Cpu) -> Self {
        let endianness = match cpu.arch.sleigh.big_endian {
            false => Endianness::Little,
            true => Endianness::Big,
        };

        let (module, functions) = init_module(endianness);
        let mut translator_ctx = TranslatorCtx::new(cpu.arch.reg_pc, endianness);
        translator_ctx.disable_jit_mem = std::env::var_os("ICICLE_DISABLE_JIT_MEM").is_some();
        translator_ctx.enable_shadow_stack = cpu.enable_shadow_stack;

        Self {
            endianness,
            builder_ctx: FunctionBuilderContext::new(),
            code_ctx: cranelift_codegen::Context::new(),
            translator_ctx,
            module,
            functions,
            il_dump: None,
            jit_hit: 0,
            jit_miss: 0,
            // Exploit the fact that `vec![]` has a specialized implementation using `#[rustc_box]`
            active: vec![(u64::MAX, runtime::call_bad_lookup_error()); FAST_LOOKUP_TABLE_SIZE]
                .into_boxed_slice()
                .try_into()
                .ok()
                .unwrap(),
            compiled: vec![],
            entry_points: HashMap::new(),
            block_mapping: HashMap::new(),
            dead: 0,
            declared_functions: vec![],
        }
    }

    pub fn clear(&mut self) {
        tracing::debug!("clearing JIT");

        self.code_ctx.clear();
        self.active.fill((u64::MAX, runtime::call_bad_lookup_error()));
        self.compiled.clear();
        self.entry_points.clear();
        self.block_mapping.clear();
        self.dead = 0;
        self.declared_functions.clear();
    }

    /// Safety: This invalidates any references to the JITed functions.
    // @fixme: Prevent any references to JITed functions from occuring outside of the JIT.
    pub unsafe fn reset(&mut self) {
        self.clear();

        // Redefine a new module
        let (mut module, functions) = init_module(self.endianness);
        std::mem::swap(&mut self.module, &mut module);
        self.functions = functions;

        // Destroy the old module
        module.free_memory();
    }

    /// Returns whether we should purge the jit cache.
    pub fn should_purge(&self) -> bool {
        // Currently we purge when more than half the blocks are dead or over a fixed threshold.
        self.dead > self.entry_points.len() / 2 || self.dead > 0x1000
    }

    /// Invalidates any generated code that references the specified block.
    pub fn invalidate(&mut self, block_id: usize) {
        if let Some(&id) = self.block_mapping.get(&block_id) {
            for &addr in &self.compiled[id] {
                self.active[Self::lookup_key(addr)] = (u64::MAX, runtime::call_bad_lookup_error());
                self.entry_points.remove(&addr);
                self.dead += 1;
            }
        }
    }

    #[inline(always)]
    fn lookup_key(addr: u64) -> usize {
        addr as usize % FAST_LOOKUP_TABLE_SIZE
    }

    #[inline(always)]
    pub fn lookup_fast(&self, addr: u64) -> Option<JitFunction> {
        let (key, entry) = self.active[Self::lookup_key(addr)];
        if addr == key { Some(entry) } else { None }
    }

    pub fn add_fast_lookup(&mut self, addr: u64, entry: JitFunction) {
        self.active[Self::lookup_key(addr)] = (addr, entry);
    }

    pub fn remove_fast_lookup(&mut self, addr: u64) {
        self.active[Self::lookup_key(addr)] = (u64::MAX, runtime::call_bad_lookup_error());
    }

    pub fn clear_fast_lookup(&mut self) {
        self.active.fill((u64::MAX, runtime::call_bad_lookup_error()));
    }

    pub fn compile(&mut self, target: &CompilationTarget) -> ModuleResult<()> {
        let (func, _size) = self.translate_and_define(target, false)?;
        self.module.finalize_definitions()?;

        for addr in target.entry_points() {
            let jit_fn = self.get_jit_func(func);
            if self.entry_points.insert(addr, jit_fn).is_some() {
                self.dead += 1;
            }
            self.active[Self::lookup_key(addr)] = (addr, jit_fn);
        }
        self.compiled.push(target.entry_points().collect());

        Ok(())
    }

    pub fn compile_debug(
        &mut self,
        target: &CompilationTarget,
    ) -> ModuleResult<(JitFunction, u32, String, String)> {
        self.il_dump = Some(String::new());
        let (func, size) = self.translate_and_define(target, true)?;

        let disasm = self
            .code_ctx
            .compiled_code()
            .as_ref()
            .and_then(|x| x.disasm.clone())
            .unwrap_or_else(|| "unknown".into());

        self.module.finalize_definitions()?;
        let jit_fn = self.get_jit_func(func);

        Ok((jit_fn, size, self.il_dump.take().unwrap(), disasm))
    }

    fn get_jit_func(&mut self, func: FuncId) -> JitFunction {
        let fn_ptr = self.module.get_finalized_function(func);
        // Safety: the finalized function is expected to be generated correctly.
        let jit_fn = unsafe { std::mem::transmute(fn_ptr) };
        jit_fn
    }

    /// Translate the pending blocks to Cranelift IR function, and define it in the module.
    fn translate_and_define(
        &mut self,
        target: &CompilationTarget,
        want_disasm: bool,
    ) -> ModuleResult<(FuncId, u32)> {
        self.module.clear_context(&mut self.code_ctx);
        self.code_ctx.want_disasm = want_disasm;
        self.code_ctx.func.signature.call_conv = self.module.isa().default_call_conv();

        let mut builder = FunctionBuilder::new(&mut self.code_ctx.func, &mut self.builder_ctx);

        // Declare all blocks that we are compiling as part of this function.
        self.translator_ctx.clear();
        for (id, guest_block) in target.iter() {
            self.translator_ctx.declare_block(&mut builder, id, guest_block);
        }

        translate::translate(
            &mut self.module,
            builder,
            &mut self.translator_ctx,
            &self.functions,
            target,
        );

        if let Some(out) = &mut self.il_dump {
            *out = debug::debug_il(&self.code_ctx, target);
        }

        let func = self.module.declare_anonymous_function(&self.code_ctx.func.signature)?;
        let size = self
            .module
            .define_function(func, &mut self.code_ctx)
            .map_err(|err| {
                let entry = target.iter().find_map(|(_, block)| block.entry).unwrap_or(0x0);
                std::fs::write(
                    format!("failed_function_{entry:#0x}.clif"),
                    debug::debug_il(&self.code_ctx, target),
                )
                .unwrap();
                err
            })?
            .size;

        for address in target.entry_points() {
            self.declared_functions.push((func, address));
        }

        Ok((func, size))
    }

    pub fn dump_jit_mapping(&self, path: &std::path::Path) -> std::io::Result<()> {
        use std::io::Write;

        let mut writer = std::io::BufWriter::new(std::fs::File::create(path)?);
        for (func_id, addr) in &self.declared_functions {
            writeln!(writer, "{func_id},{addr:#x}")?;
        }

        Ok(())
    }
}

fn init_module(endianness: Endianness) -> (JITModule, RuntimeFunctions) {
    let mut flag_builder = cranelift_codegen::settings::builder();

    // We will never relocate the JITed code, so we don't use position-independent-code to avoid
    // needing a GOT. (Note: this currently has a minimal impact on performance).
    flag_builder.set("is_pic", "false").unwrap();

    // Required since we use u128's as part of runtime functions (load/store).
    flag_builder.set("enable_llvm_abi_extensions", "true").unwrap();

    // Always enable frame pointers to make debugging easier.
    flag_builder.set("preserve_frame_pointers", "true").unwrap();

    // The verifier is quite slow, but generally we want it enabled for now to catch bugs while
    // the JIT is being developed and we keep upgrading cranelift versions.
    //
    // Note: default if this flag is not set is enabled.
    if let Ok(value) = std::env::var("ICICLE_ENABLE_JIT_VERIFIER") {
        flag_builder.set("enable_verifier", &value).unwrap();
    }

    // We use a default optmization level of `none` since Cranelift's current optimizations appear
    // to have little runtime impact, but result in slower compilation time.
    let opt_level = std::env::var("OPT_LEVEL").unwrap_or_else(|_| "none".to_string());
    flag_builder.set("opt_level", &opt_level).unwrap();

    if let Ok(value) = std::env::var("CRANELIFT_USE_EGRAPHS") {
        flag_builder.set("use_egraphs", &value).unwrap();
    }

    let flags = settings::Flags::new(flag_builder);
    tracing::trace!("cranelift flags: {}", flags.to_string());

    let isa_builder = cranelift_native::builder().expect("host machine is not supported");
    let isa = isa_builder.finish(flags).expect("failed to create isa");
    let mut builder = JITBuilder::with_isa(isa, cranelift_module::default_libcall_names());

    macro_rules! define_fn_symbol {
        ($func:path) => {{ define_fn_symbol!(stringify!($func), $func) }};
        ($name:expr, $func:path) => {{
            builder.symbol($name, $func as *const u8);
        }};
    }

    define_fn_symbol!("load8", runtime::load8);
    define_fn_symbol!("store8", runtime::store8);
    match endianness {
        Endianness::Big => {
            define_fn_symbol!("load16", runtime::load16be);
            define_fn_symbol!("load32", runtime::load32be);
            define_fn_symbol!("load64", runtime::load64be);
            define_fn_symbol!("load128", runtime::load128be);

            define_fn_symbol!("store16", runtime::store16be);
            define_fn_symbol!("store32", runtime::store32be);
            define_fn_symbol!("store64", runtime::store64be);
            define_fn_symbol!("store128", runtime::store128be);
        }
        Endianness::Little => {
            define_fn_symbol!("load16", runtime::load16le);
            define_fn_symbol!("load32", runtime::load32le);
            define_fn_symbol!("load64", runtime::load64le);
            define_fn_symbol!("load128", runtime::load128le);

            define_fn_symbol!("store16", runtime::store16le);
            define_fn_symbol!("store32", runtime::store32le);
            define_fn_symbol!("store64", runtime::store64le);
            define_fn_symbol!("store128", runtime::store128le);
        }
    }

    define_fn_symbol!(runtime::push_shadow_stack);
    define_fn_symbol!(runtime::pop_shadow_stack);
    define_fn_symbol!(runtime::run_interpreter);

    let mut module = JITModule::new(builder);
    tracing::debug!(
        "JIT module created with isa={:?}, calling conv={:?}",
        module.isa(),
        module.isa().default_call_conv()
    );

    let functions =
        declare_runtime_functions(&mut module).expect("Failed to declared runtime functions");

    (module, functions)
}

fn declare_runtime_functions(module: &mut JITModule) -> ModuleResult<RuntimeFunctions> {
    use types::{I16, I32, I64, I8};

    let call_conv = module.isa().default_call_conv();

    macro_rules! import_fn {
        ($name:expr, ($($arg_ty:expr),*) -> ($($ret_ty:expr),*)) => {{
            let mut sig = Signature::new(call_conv);
            for arg in &[$($arg_ty),*] {
                sig.params.push(AbiParam::new(*arg));
            }
            for ret in &[$($ret_ty),*] {
                sig.returns.push(AbiParam::new(*ret));
            }
            module.declare_function($name, Linkage::Import, &sig)?
        }};
    }

    Ok(RuntimeFunctions {
        mmu: MemHandler {
            load8: import_fn!("load8", (I64, I64) -> (I8)),
            load16: import_fn!("load16", (I64, I64) -> (I16)),
            load32: import_fn!("load32", (I64, I64) -> (I32)),
            load64: import_fn!("load64", (I64, I64) -> (I64)),
            load128: import_fn!("load128", (I64, I64, I64) -> ()),

            store8: import_fn!("store8", (I64, I64, I8) -> ()),
            store16: import_fn!("store16", (I64, I64, I16) -> ()),
            store32: import_fn!("store32", (I64, I64, I32) -> ()),
            store64: import_fn!("store64", (I64, I64, I64) -> ()),
            store128: import_fn!("store128", (I64, I64, I64, I64) -> ()),
        },

        push_shadow_stack: import_fn!("runtime::push_shadow_stack", (I64, I64) -> ()),
        pop_shadow_stack: import_fn!("runtime::pop_shadow_stack", (I64, I64) -> ()),

        run_interpreter: import_fn!("runtime::run_interpreter", (I64, I64, I64, I64, I64) -> ()),

        hook_signature: {
            let mut sig = Signature::new(call_conv);
            sig.params.push(AbiParam::new(I64)); // cpu_ptr
            sig.params.push(AbiParam::new(I64)); // pc
            sig.params.push(AbiParam::new(I64)); // data_ptr
            sig
        },
    })
}
