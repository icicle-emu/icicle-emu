use std::io::Write;

use afl_icicle_trace::{forkserver_init, log_error_and_exit, ForkserverFuzzer};
use icicle_fuzzing::FuzzConfig;

fn main() {
    forkserver_init();
    eprintln!("[icicle] icicle started");

    let logger = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_env("ICICLE_LOG"))
        .without_time();

    match std::env::var("ICICLE_LOG_ADDR").ok() {
        Some(addr) => logger
            .with_writer(move || {
                std::io::BufWriter::new(icicle_vm::cpu::utils::UdpWriter::new(&addr))
            })
            .init(),
        None => logger.with_writer(std::io::stderr).init(),
    }

    let config = FuzzConfig::load().expect("Invalid config");

    if let Some(dir) = std::env::var_os("ICICLE_BLOCK_COVERAGE") {
        if let Err(e) = collect_coverage(config, dir.as_ref()) {
            log_error_and_exit(e);
        }
        return;
    }

    if let Err(e) = icicle_fuzzing::run_auto(config, ForkserverFuzzer) {
        log_error_and_exit(e);
    }
}

fn collect_coverage(mut config: FuzzConfig, dir: &std::path::Path) -> anyhow::Result<()> {
    let (_total, entries) =
        icicle_fuzzing::trace::resolve_block_coverage(&mut config, dir.to_path_buf())?;

    let mut output = vec![];
    for entry in entries {
        let mut cov: Vec<_> = entry.new.into_iter().collect();
        cov.sort_unstable();
        output.push(serde_json::json!({
            "input": entry.tag.to_string_lossy(),
            "new_coverage": cov
        }));
    }

    write!(std::io::stdout(), "{}", serde_json::json!(output))?;
    Ok(())
}
