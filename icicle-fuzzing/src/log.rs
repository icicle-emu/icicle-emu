use std::collections::HashSet;

use icicle_vm::{Vm, VmExit};

#[derive(Default)]
pub struct CrashLogger {
    crashes: HashSet<(u64, String)>,
}

impl CrashLogger {
    pub fn check_crash(&mut self, vm: &mut Vm, exit: VmExit) -> bool {
        let pc = vm.cpu.read_pc();
        let key = crate::gen_crash_key(vm, exit);
        self.crashes.insert((pc, key))
    }
}

pub struct StatsLogger {
    output: std::io::BufWriter<std::fs::File>,

    start_time: std::time::Instant,
    last_log: std::time::Instant,
    log_rate: std::time::Duration,

    total_execs: u64,
    total_input_bytes: u64,
}

impl StatsLogger {
    pub fn init() -> Option<Self> {
        let path = std::env::var_os("ICICLE_LOG_PATH")?;
        let output = std::io::BufWriter::new(std::fs::File::create(path).ok()?);

        Some(Self {
            output,
            start_time: std::time::Instant::now(),
            last_log: std::time::Instant::now(),
            log_rate: std::time::Duration::from_secs(1),

            total_execs: 0,
            total_input_bytes: 0,
        })
    }

    pub fn log_exec(&mut self, input_size: usize) {
        use std::io::Write;

        let now = std::time::Instant::now();

        if self.total_execs == 0 {
            let _ = writeln!(self.output, "time,execs,input_bytes");
            self.start_time = now;
        }

        self.total_execs += 1;
        self.total_input_bytes += input_size as u64;

        if self.last_log.elapsed() > self.log_rate {
            self.last_log = now;
            let _ = writeln!(
                self.output,
                "{},{},{}",
                (now - self.start_time).as_secs_f64(),
                self.total_execs,
                self.total_input_bytes
            );
        }

        let _ = self.output.flush();
    }
}
