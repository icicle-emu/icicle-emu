use std::cell::UnsafeCell;

use icicle_fuzzing::cmplog::CmpMap;

/// The default size of the bitmap used to store coverage information.
const MAP_SIZE_POW2: usize = 16;
pub const MAP_SIZE: usize = 1 << MAP_SIZE_POW2;

/// The environment variable that stores the ID for the shared memory section, used for sharing
/// the coverage bitmap.
const SHM_ENV_VAR: &str = "__AFL_SHM_ID";

/// The environment variable that keeps track of the coverage map size.
const MAP_SIZE_ENV_VAR: &str = "MAP_SIZE";

/// The environment variable that stores the ID for shared memory section used for sharing
/// inputs.
const SHM_FUZZ_ENV_VAR: &str = "__AFL_SHM_FUZZ_ID";

/// The environment variable that stores the ID for the CmpLog area.
const SHM_CMPLOG_ENV_VAR: &str = "__AFL_CMPLOG_SHM_ID";
pub const IS_CMPLOG_FORK_SERVER: &str = "___AFL_EINS_ZWEI_POLIZEI___";

#[allow(rustdoc::private_intra_doc_links)]
/// Returns whether the program was invoked by AFL++ by checking [SHM_ENV_VAR].
pub fn is_afl_connected() -> bool {
    std::env::var_os(SHM_ENV_VAR).is_some()
}

/// Returns the map size of the AFL coverage area
fn map_size() -> anyhow::Result<usize> {
    let map_size_str = match std::env::var_os(MAP_SIZE_ENV_VAR) {
        Some(var) => var,
        None => return Ok(MAP_SIZE),
    };

    map_size_str
        .into_string()
        .map_err(|_| anyhow::anyhow!("invalid map size"))?
        .parse()
        .map_err(|e| anyhow::format_err!("`MAP_SIZE` invalid: {}", e))
}

#[cfg(not(unix))]
unsafe fn shared_memory_from_env(_: &str) -> anyhow::Result<*mut u8> {
    anyhow::bail!("shared memory not supported on current platform");
}

#[cfg(unix)]
unsafe fn shared_memory_from_env(env: &str) -> anyhow::Result<*mut u8> {
    let id_str =
        std::env::var(env).map_err(|e| anyhow::format_err!("Failed to get `{}`: {}", env, e))?;
    let shm_id: i32 =
        id_str.parse().map_err(|e| anyhow::format_err!("`{}` invalid: {}", env, e))?;

    let map = libc::shmat(shm_id, std::ptr::null(), 0);
    if map == std::ptr::null_mut() || map == (-1_isize as *mut libc::c_void) {
        anyhow::bail!(
            "Error getting shared memory: shmat error: {}",
            std::io::Error::last_os_error()
        );
    }

    // Check for 64-bit alignment
    // @todo: check if this is actually required, we do this just to be safe for now.
    if (map as usize) & ((1 << std::mem::size_of::<u64>()) - 1) != 0 {
        anyhow::bail!("Shared memory region was not 64-bit aligned");
    }

    Ok(map as *mut u8)
}

/// Retrieve the shared memory section corresponding to `afl_area`.
///
/// Safety: parent process is responsible for ensuring that [SHM_ENV_VAR] corresponds to a valid
/// shared memory section of size [MAP_SIZE] that lives as long as this process.
pub unsafe fn afl_area() -> anyhow::Result<(*mut u8, usize)> {
    let map = shared_memory_from_env(SHM_ENV_VAR)?;
    let size = map_size()?;
    Ok((map, size))
}

/// Retrieve the shared memory section corresponding to the input test-cases.
///
/// Safety: parent process is responsible for ensuring that [SHM_FUZZ_ENV_VAR] corresponds to a
/// valid shared memory section that lives as long as this process where the first [u32]
/// corresponds to the length of the region.
pub unsafe fn input() -> anyhow::Result<*mut u8> {
    shared_memory_from_env(SHM_FUZZ_ENV_VAR)
}

/// Retrieve the shared memory section corresponding to `__afl_cmp_map`.
///
/// Safety: parent process is responsible for ensuring that [SHM_ENV_VAR] corresponds to a valid
/// shared memory section of size [MAP_SIZE] that lives as long as this process.
pub unsafe fn cmplog_map() -> anyhow::Result<&'static UnsafeCell<CmpMap>> {
    let map = shared_memory_from_env(SHM_CMPLOG_ENV_VAR)?;
    Ok(&*(map as *mut UnsafeCell<CmpMap>))
}
