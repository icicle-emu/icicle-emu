# Icicle

Icicle is an experimental fuzzing-specific, multi-architecture emulation framework.


* [afl-icicle-trace](./afl-icicle-trace) - A wrapper binary to allow running Icicle under AFL++ and replaying inputs.
* [icicle-cpu](./icicle-cpu) - Core CPU state, SLEIGH management, and interface trait definitions.
* [icicle-fuzzing](./icicle-fuzzing) - Fuzzing instrumentation and harnessing.
* [icicle-gdb](./icicle-gdb) - GDB integration.
* [icicle-jit](./icicle-jit) - JIT backend for IL.
* [icicle-linux](./icicle-linux) - Linux userspace emulator
* [icicle-mem](./icicle-mem) - Software virtual memory and address translation implementation.
* [icicle-test](./icicle-test) - Unit tests for instruction semantics.
* [icicle-vm](./icicle-vm) - P-code interpreter and state management.
* [sleigh](./sleigh) - A custom SLEIGH runtime that handles parsing, compiling, and using SLEIGH specifications.


## Usage

Icicle must be built before any examples will run:

```
cargo build --release
```

### Fuzzing using AFL++

The `afl-icicle-trace` binary implements an AFL++ compatible interface that can be used to fuzz arbitary binaries using AFL++'s `AFL_QEMU_CUSTOM_BIN` support.

As an example, to fuzz the `base64` binary from the LAVA-M dataset for x86-64 we can run:

```bash
ICICLE_SYSROOT=../sysroots/x86_64 ICICLE_ARCH=x86_64-linux AFL_QEMU_CUSTOM_BIN=1 ../AFLplusplus/afl-fuzz -t 10000 -Q -i ../inputs/generic -o workdir -- ./target/release/afl-icicle-trace /bin/lava/base64 -d
```

* `ICICLE_SYSROOT`: controls the path configured for the virtual file system (VFS) implemented by the Linux emulator.
* `ICICLE_ARCH`: specifies the target triple that the fuzzing harness should configure the emulator for running. Other examples include `aarch64-linux`, `mipsel-linux`, `msp430-none`.


For MSP430 fuzzing, the path to a MCU configuration file needs to be provided to the fuzzer:

```bash
MSP430_MCU=../msp430-mcu/cc430f6137.ron ICICLE_ARCH=msp430-none AFL_QEMU_CUSTOM_BIN=1 ../AFLplusplus/afl-fuzz -t 10000 -Q -i ../inputs/generic -o workdir -- ./target/release/afl-icicle-trace ../sysroots/msp430/goodwatch.elf
```


### Replaying inputs

The `afl-icicle-trace` binary also supports running the emulator with a specific input, e.g.:

```bash
ICICLE_SYSROOT=../sysroots/x86_64 ICICLE_ARCH=x86_64-linux ./target/release/afl-icicle-trace /bin/lava/base64 < README.md
```

Icicle also implements several utilities for analysing fuzzing results. Including:

* A stack based crash resolver that can be run over all the crashes discovered during a fuzzing session:
    ```
    ICICLE_RESOLVE_CRASHES=workdir/default/crashes/ ICICLE_SYSROOT=../sysroots/x86_64 ICICLE_ARCH=x86_64-linux ./target/release/afl-icicle-trace /bin/lava/base64 | jq
    ```

* And block coverage resolver:
    ```
    ICICLE_RESOLVE_CRASHES=workdir/default/crashes/ ICICLE_SYSROOT=../sysroots/x86_64 ICICLE_ARCH=x86_64-linux ./target/release/afl-icicle-trace /bin/lava/base64 | jq
    ```

### Using Icicle as a library

Icicle can also be used as a library, in a similar to Unicorn:

In `Cargo.toml` add:

```toml
[dependencies]
icicle-vm = { git = "https://github.com/icicle-emu/icicle-emu" }
pcode = { git = "https://github.com/icicle-emu/icicle-emu" }
```

```rust
fn main() {
    // Setup the CPU state for the target triple
    let mut cpu_config = icicle_vm::cpu::Config::from_target_triple("x86_64-none");
    let mut vm = icicle_vm::build(&cpu_config).unwrap();

    // Setup an environment to run inside of.
    let mut env = icicle_vm::env::build_auto(&mut vm).unwrap();
    // Load a binary into the environment.
    env.load(&mut vm.cpu, b"./test.elf").unwrap();
    vm.env = env;

    // Add instrumentation
    let counter = vm.cpu.trace.register_store(vec![0_u64]);
    vm.add_injector(BlockCounter { counter });

    // Run until the VM exits.
    let exit = vm.run();
    println!("{exit:?}\n{}", icicle_vm::debug::current_disasm(&mut vm));


    // Read instrumentation data.
    let blocks_hit = vm.cpu.trace[counter].as_any().downcast_ref::<Vec<u64>>().unwrap()[0];
    let blocks_executed = blocks_hit.saturating_sub(1);
    println!("{blocks_executed} blocks were executed");
}

struct BlockCounter {
    counter: icicle_vm::cpu::StoreRef,
}

impl icicle_vm::CodeInjector for BlockCounter {
    fn inject(
        &mut self,
        _cpu: &mut icicle_vm::cpu::Cpu,
        group: &icicle_vm::cpu::BlockGroup,
        code: &mut icicle_vm::BlockTable,
    ) {
        let store_id = self.counter.get_store_id();
        for block in &mut code.blocks[group.range()] {
            // counter += 1
            let counter = block.pcode.alloc_tmp(8);
            let instrumentation = [
                (counter, pcode::Op::Load(store_id), 0_u64).into(),
                (counter, pcode::Op::IntAdd, (counter, 1_u64)).into(),
                (pcode::Op::Store(store_id), (0_u64, counter)).into(),
            ];

            // Inject the instrumentation at the start of the block.
            block.pcode.instructions.splice(..0, instrumentation);
        }
    }
}
```

## License

Icicle is dual-licensed under either:

* MIT License ([LICENSE-MIT](./LICENSE-MIT))
* OR Apache License, Version 2.0 ([LICENSE-APACHE](./LICENSE-APACHE))


## Copyright

Copyright (c) Cyber Security Research Centre Limited 2023. This work has been supported by the Cyber Security Research Centre (CSCRC) Limited whose activities are partially funded by the Australian Government's Cooperative Research Centres Programme. We are currently tracking the impact CSCRC funded research. If you have used this code in your project, please contact us at contact@cybersecuritycrc.org.au to let us know.
