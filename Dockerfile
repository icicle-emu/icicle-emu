from ubuntu:22.04

arg SUPPORTED_GHIDRA_SHA256=77373649fd96bc3f7c6c34bc76df0b276d913131

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
    git remote add origin https://github.com/NationalSecurityAgency/ghidra.git && \
    git -c http.sslVerify=false fetch --depth 1 origin ${SUPPORTED_GHIDRA_SHA256} && \
    git checkout FETCH_HEAD 

# Copy in the icicle source
workdir /src/icicle-emu
copy . .

# Link Ghidra
run ln -s /src/ghidra/Ghidra ./Ghidra

# Build
run /root/.cargo/bin/cargo build --release
