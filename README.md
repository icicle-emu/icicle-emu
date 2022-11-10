# Icicle

An experimental emulator for fuzzing.

## Usage

The emulator is primarily designed to be used as a library for a fuzzer, however `afl-icicle-trace` implements an AFL/AFL++ compatible interface for direct usage. e.g.

```bash
cargo build --release

mkdir workdir
ICICLE_SYSROOT=../sysroots/x86_64 ICICLE_ARCH=x86_64-linux AFL_QEMU_CUSTOM_BIN=1 ../AFLplusplus/afl-fuzz -t 10000 -Q -i ../inputs/generic -o workdir -- ./target/release/afl-icicle-trace /bin/lava/base64 -d
```
