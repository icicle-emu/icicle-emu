from ubuntu:22.04

arg GHIDRA_SUPPORTED_SHA256=50230050fa58bd40d5a96cab9c167fc55bc92a76
arg GHIDRA_REMOTE='https://github.com/icicle-emu/ghidra.git'

env DEBIAN_FRONTEND=none

run apt update && apt install -y \
    curl \
    git \
    gcc

# Install rust
run curl https://sh.rustup.rs -sSf | \
    sh -s -- --default-toolchain nightly --profile minimal -y

# Get ghidra
workdir /src/ghidra
run git init && \
    git remote add origin ${GHIDRA_REMOTE} && \
    git -c http.sslVerify=false fetch --depth 1 origin ${GHIDRA_SUPPORTED_SHA256} && \
    git checkout FETCH_HEAD 
env GHIDRA_SRC=/src/ghidra

# Copy in the icicle source
workdir /src/icicle-emu
copy . .

# Link Ghidra
run ln -s /src/ghidra/Ghidra ./Ghidra

# Build
run /root/.cargo/bin/cargo build --release
