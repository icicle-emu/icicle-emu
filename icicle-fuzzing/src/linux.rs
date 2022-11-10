//! Module for fuzzing linux binaries
use std::path::PathBuf;

use icicle_vm::{
    cpu::{Environment, ExceptionCode},
    linux::fs::devices::ReadableSharedBufDevice,
    VmExit,
};

use crate::{parse_u64_with_prefix, FuzzConfig, FuzzTarget, Runnable};

pub struct LinuxConfig {
    /// Whether stdout/stderr should be mounted.
    pub mount_stdout: bool,

    /// The path to mount the fuzzer input at.
    pub mount_path: String,

    /// The path to use as the sysroot.
    pub sysroot: PathBuf,

    /// Configures whether shared libraries should be instrumented.
    pub instrument_libs: bool,

    /// Configures whether the kernel should report a crash on oversized allocations.
    pub kill_on_alloc_failure: bool,

    /// Overwrites the maximum allocation size for the kernel.
    pub max_alloc_size: Option<u64>,
}

impl LinuxConfig {
    pub fn from_env() -> Self {
        Self {
            mount_path: std::env::var("ICICLE_MOUNT_PATH").unwrap_or_else(|_| "/dev/stdin".into()),
            mount_stdout: false,
            sysroot: std::env::var_os("ICICLE_SYSROOT")
                .map_or_else(|| PathBuf::from("/"), PathBuf::from),
            instrument_libs: std::env::var("AFL_INST_LIBS").map_or(false, |x| x == "1"),
            max_alloc_size: std::env::var("ICICLE_MAX_ALLOC_SIZE")
                .map(|x| parse_u64_with_prefix(&x).unwrap())
                .ok(),
            kill_on_alloc_failure: std::env::var("ICICLE_KILL_ON_ALLOC_FAILURE")
                .map_or(false, |x| x == "1"),
        }
    }
}

#[derive(Clone)]
pub struct Target {
    pub buf: ReadableSharedBufDevice,
}

impl Target {
    pub fn new() -> Self {
        Self { buf: ReadableSharedBufDevice::new() }
    }
}

impl FuzzTarget for Target {
    fn initialize_vm<I, F>(
        &mut self,
        config: &mut FuzzConfig,
        instrument_vm: F,
    ) -> anyhow::Result<(icicle_vm::Vm, I)>
    where
        F: FnOnce(&mut icicle_vm::Vm, &FuzzConfig) -> anyhow::Result<I>,
    {
        let mut vm = icicle_vm::build(&config.cpu_config())?;
        let mut env = icicle_vm::env::build_linux_env(
            &mut vm,
            &icicle_vm::linux::KernelConfig {
                zero_stack: true,
                max_alloc_size: Some(config.linux.max_alloc_size.unwrap_or(1 << 24)),
                kill_on_alloc_failure: config.linux.kill_on_alloc_failure,
                ..Default::default()
            },
            config.linux.sysroot.clone(),
            config.linux.mount_stdout,
        )?;

        // Create a hook for the first time the input is read
        let mount_path = &config.linux.mount_path;
        env.vfs.hook_path(mount_path.as_bytes()).map_err(|e| {
            anyhow::format_err!("failed to create file hook for {}: {}", mount_path, e)
        })?;

        let args = &config.guest_args;

        let mut envs = vec![];
        envs.push((&b"LD_BIND_NOW"[..], &b"1"[..]));
        let guest_env = std::env::var("ICICLE_SET_ENV");
        if let Ok(guest_env) = guest_env.as_ref() {
            // @fixme: this is broken if the environment variable contains internal commas (but it's
            // also broken in QEMU).
            for env in guest_env.split(',') {
                let mut parts = env.splitn(2, '=');
                match (parts.next(), parts.next()) {
                    (Some(key), Some(value)) => envs.push((key.as_bytes(), value.as_bytes())),
                    _ => return Err(anyhow::format_err!("invalid environment variable: {}", env)),
                }
            }
        }

        env.process.args.set(&args[0], &args[1..], &envs);
        env.load(&mut vm.cpu, config.guest_args[0].as_bytes())
            .map_err(|e| anyhow::format_err!("{e}"))?;
        vm.env = Box::new(env);

        // Add instrumentation to the VM. This needs to be done before we run for the first time
        // since blocks are cached, and currently we don't support invalidating blocks based
        // on instrumentation changes.
        let instrumentation = (instrument_vm)(&mut vm, config)?;

        // Run until we reach our custom error hook then create a snapshot
        match vm.run() {
            VmExit::UnhandledException((ExceptionCode::Environment, 0x1)) => {}
            other => {
                let backtrace = icicle_vm::debug::backtrace(&mut vm);
                anyhow::bail!(
                    "Unexpected exit when finding read to file hook: {other:?}\n{backtrace}"
                )
            }
        }

        let env = vm.env.as_any().downcast_mut::<icicle_vm::linux::Kernel>().unwrap();
        env.vfs
            .create_dev(b"/dev/stdin", self.buf.clone())
            .map_err(|e| anyhow::format_err!("Failed to set input: {}", e))?;

        let bt = icicle_vm::debug::backtrace(&mut vm);
        let icount = vm.cpu.icount;
        tracing::info!("First use of input after {icount} instructions: \n{bt}\n-----------",);

        Ok((vm, instrumentation))
    }
}

impl Runnable for Target {
    fn set_input(&mut self, _vm: &mut icicle_vm::Vm, input: &[u8]) -> anyhow::Result<()> {
        self.buf.set(input).map_err(|e| anyhow::format_err!("Failed to set input: {}", e))
    }

    fn input_buf(&self) -> Option<&ReadableSharedBufDevice> {
        Some(&self.buf)
    }
}
