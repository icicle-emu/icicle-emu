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

```rust
fn main() {
    // Setup the CPU state for the target triple
    let cpu_config = icicle_vm::cpu::Config::from_triple("target-triple").unwrap();
    let mut vm = icicle_vm::build(&cpu_config).unwrap()

    // Setup an environment to run inside of.
    let mut env = icicle_vm::env::build_auto(&mut vm).unwrap();
    // Load a binary into the environment.
    env.load(&mut vm.cpu, "path/to/binary").unwrap();
    vm.env = Box::new(env);

    // Add instrumentation
    let storage = vm.cpu.trace.register_store(...);
    vm.add_injector(...);

    // Run until the VM exits.
    let exit = vm.run().unwrap();
    println!("{exit:?}");
}
```

## License

Icicle is dual-licensed under either:

* MIT License ([LICENSE-MIT](./LICENSE-MIT))
* OR Apache License, Version 2.0 ([LICENSE-APACHE](./LICENSE-APACHE))


## Copyright

Copyright (c) Cyber Security Research Centre Limited 2023. This work has been supported by the Cyber Security Research Centre (CSCRC) Limited whose activities are partially funded by the Australian Government's Cooperative Research Centres Programme. We are currently tracking the impact CSCRC funded research. If you have used this code in your project, please contact us at contact@cybersecuritycrc.org.au to let us know.
