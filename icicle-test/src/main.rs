use std::path::Path;

use anyhow::Context;
use icicle_vm::cpu::mem::perm;

use crate::tester::Tester;

mod parser;
mod tester;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_env("ICICLE_LOG"))
        .without_time()
        .with_writer(|| {
            std::io::BufWriter::new(icicle_vm::cpu::utils::UdpWriter::new("127.0.0.1:9500"))
        })
        .init();

    if let Err(e) = run() {
        eprintln!("{:?}", e);
    }
}

enum TestMode {
    All,
    Debug,
    One(String, String),
    Trace(String, String),
    TraceNoOpt(String, String),
    Bench,
    Fib,
}

fn run() -> anyhow::Result<()> {
    let mode_str = std::env::args().nth(1);
    let mode = match mode_str.as_deref() {
        Some("all") => TestMode::All,
        Some("debug") => TestMode::Debug,
        Some("bench") => TestMode::Bench,
        Some("fib") => TestMode::Fib,
        Some("trace") => {
            let arch =
                std::env::args().nth(2).ok_or_else(|| anyhow::format_err!("Expected test file"))?;
            let test =
                std::env::args().nth(3).ok_or_else(|| anyhow::format_err!("Expected test file"))?;
            TestMode::Trace(arch, test)
        }
        Some("trace-no-opt") => {
            let arch =
                std::env::args().nth(2).ok_or_else(|| anyhow::format_err!("Expected test file"))?;
            let test =
                std::env::args().nth(3).ok_or_else(|| anyhow::format_err!("Expected test file"))?;
            TestMode::TraceNoOpt(arch, test)
        }
        Some(arch) => {
            let test =
                std::env::args().nth(2).ok_or_else(|| anyhow::format_err!("Expected test file"))?;
            TestMode::One(arch.to_owned(), test)
        }
        _ => TestMode::All,
    };

    let disable_jit = std::env::var("ICICLE_DISABLE_JIT").is_ok();

    let test_icicle_cpu = |triple_str: &str, config: TestConfig| -> anyhow::Result<()> {
        let triple: target_lexicon::Triple =
            triple_str.parse().map_err(|_| anyhow::format_err!("Unknown target: {triple_str}"))?;

        let cpu_config = icicle_vm::cpu::Config {
            triple,
            enable_jit: !disable_jit,
            optimize_instructions: config.optimize,
            optimize_block: config.optimize,
            ..Default::default()
        };

        let mut vm = icicle_vm::build(&cpu_config)
            .map_err(|e| anyhow::format_err!("Failed to build {triple_str}: {e}"))?;

        if config.dump_il {
            vm.jit.il_dump = Some(String::new());
        }

        let result = run_test_and_print(&mut vm, &config);

        if let Some(il_dump) = &vm.jit.il_dump {
            std::fs::write("translated.clif", il_dump).unwrap();
        }

        result
    };

    match mode {
        TestMode::All => {
            test_icicle_cpu("x86_64", TestConfig::default("x64"))?;
            test_icicle_cpu("i386", TestConfig::default("x86"))?;
            test_icicle_cpu("mipsel", TestConfig::default("mipsel"))?;
            test_icicle_cpu("mips", TestConfig::default("mips"))?;
            test_icicle_cpu("riscv64", TestConfig::default("riscv64gc"))?;
            test_icicle_cpu("msp430", TestConfig::default("msp430x"))?;
            test_icicle_cpu("arm", TestConfig::default("arm"))?;
            test_icicle_cpu("aarch64", TestConfig::default("aarch64"))?;
            test_icicle_cpu("powerpc", TestConfig::default("powerpc"))?;
        }
        TestMode::Debug => {
            test_icicle_cpu("x86_64", TestConfig {
                dump_il: true,
                ..TestConfig::default("x64_one")
            })?;
        }
        TestMode::Bench => {
            // Current bench results:
            //  - (debug)   0.3566 s / iter, 0.0944 ms / inst
            //  - (release) 0.0226 s / iter, 0.0060 ms / inst
            run_bench("x86_64", &TestConfig {
                save_pcode: false,
                ..TestConfig::default("fib-static")
            })?;
        }
        TestMode::Fib => {
            test_icicle_cpu("x86_64", TestConfig {
                save_pcode: false,
                ..TestConfig::default("fib-static")
            })?;
        }
        TestMode::One(name, test) => {
            test_icicle_cpu(&name, TestConfig::default(&test))?;
        }
        TestMode::Trace(name, test) => {
            test_icicle_cpu(&name, TestConfig {
                save_pcode: true,
                trace: true,
                optimize: true,
                dump_il: true,
                ..TestConfig::default(&test)
            })?;
        }
        TestMode::TraceNoOpt(name, test) => {
            test_icicle_cpu(&name, TestConfig {
                save_pcode: true,
                trace: true,
                optimize: false,
                dump_il: true,
                ..TestConfig::default(&test)
            })?;
        }
    }

    Ok(())
}

fn run_bench(triple: &str, config: &TestConfig) -> anyhow::Result<()> {
    let path = Path::new("./tests").join(&format!("{}.ins", config.group));
    let input = std::fs::read_to_string(&path)
        .with_context(|| anyhow::format_err!("Failed to load: {}", path.display()))?;
    let mut parser = parser::Parser::new(&input);

    let triple: target_lexicon::Triple =
        triple.parse().map_err(|_| anyhow::format_err!("Unknown target: {}", triple))?;

    let (sleigh, context) = icicle_vm::build_sleigh_for(triple.architecture)?;
    let mut source = icicle_vm::cpu::utils::BasicInstructionSource::new(sleigh);
    let mut lifter = icicle_vm::cpu::lifter::InstructionLifter::new();
    lifter.set_context(context);

    let mut cases = vec![];
    while let Some(Ok(test)) = parser.parse_next() {
        cases.push(test);
    }

    let mut il_count = 0;
    let times = if cfg!(debug_assertions) { 10 } else { 1000 };

    let mut buf = vec![];

    let now = std::time::Instant::now();
    for _ in 0..times {
        for test in &cases {
            buf.clear();
            test.instructions.iter().map(|x| &x.bytes).for_each(|x| buf.extend(x));

            source.set_inst(test.load_addr, &buf);

            // @fixme: handle cases where there are multiple instructions in the testcase.
            lifter
                .lift(&mut source, test.load_addr)
                .ok_or_else(|| anyhow::format_err!("Failed to lift: {:#0x}", test.load_addr))?;
            il_count += lifter.lifted.instructions.len();
        }
    }

    let seconds = now.elapsed().as_secs_f64();
    eprintln!(
        "{:.4} s / iter, {:.4} ms / inst, {:.1} instructions / sec ({} il instructions for {} cases)",
        seconds / times as f64,
        seconds / times as f64 / cases.len() as f64 * 1000.0,
        (cases.len() as f64 * times as f64) / seconds,
        il_count / times,
        cases.len()
    );

    Ok(())
}

fn run_test_and_print<T: Tester>(tester: &mut T, config: &TestConfig) -> anyhow::Result<()> {
    let (count, skip, errors) = run_test(tester, config)?;
    eprintln!("{}.ins: {} tests, {} skipped, {} errors", config.group, count, skip, errors.len());
    for error in errors {
        eprintln!("\t{}", error);
    }
    Ok(())
}

#[derive(Clone)]
struct TestConfig<'a> {
    group: &'a str,
    save_pcode: bool,
    #[allow(dead_code)]
    dump_il: bool,
    #[allow(dead_code)]
    trace: bool,
    optimize: bool,
}

impl<'a> TestConfig<'a> {
    fn default(group: &'a str) -> Self {
        Self { group, optimize: true, save_pcode: true, dump_il: false, trace: false }
    }
}

fn run_test<T: Tester>(
    tester: &mut T,
    config: &TestConfig,
) -> anyhow::Result<(usize, usize, Vec<String>)> {
    if config.save_pcode {
        clear_pcode(config.group)?;
    }

    let path = Path::new("./tests").join(&format!("{}.ins", config.group));
    let mut errors = vec![];

    let input = std::fs::read_to_string(&path)
        .with_context(|| anyhow::format_err!("Failed to load: {}", path.display()))?;

    let mut parser = parser::Parser::new(&input);
    let mut count = 0;
    let mut skip = 0;
    loop {
        let test_case = match parser.parse_next() {
            Some(Ok(test)) => test,
            Some(Err(e)) => return Err(e.context(format!("Error parsing: {}", path.display()))),
            None => break,
        };
        count += 1;
        let display_prefix = format!("{}:{}", path.display(), test_case.start_line);

        if test_case.skip {
            tracing::info!("skipping: {}", display_prefix);
            skip += 1;
            continue;
        }

        if let Err(e) = check_one(config, tester, &test_case) {
            errors.push(format!("[{}] {:?}", display_prefix, e));
        }
    }

    Ok((count, skip, errors))
}

#[derive(Debug)]
pub struct TestCase<'a> {
    load_addr: u64,
    isa_mode: u8,
    start_line: usize,
    instructions: Vec<DecodeTest<'a>>,
    semantics: Vec<SemanticsTest<'a>>,
    skip: bool,
}

#[derive(Debug)]
struct DecodeTest<'a> {
    bytes: Vec<u8>,
    expected_len: usize,
    disasm: &'a str,
    line: usize,
}

#[derive(Debug)]
struct SemanticsTest<'a> {
    inputs: Vec<Assignment<'a>>,
    outputs: Vec<Assignment<'a>>,
    line: usize,
}

#[derive(Debug, Clone)]
pub enum Assignment<'a> {
    Mem { addr: u64, perm: u8, value: Vec<u8> },
    Register { name: &'a str, value: u128 },
}

impl<'a> std::fmt::Display for Assignment<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Assignment::Mem { addr, perm, value } => {
                let bytes = icicle_vm::cpu::utils::format_bytes(value);
                if *perm == perm::NONE {
                    write!(f, "mem[{:#0x}] = {}", addr, bytes)
                }
                else {
                    let perm = perm::display(*perm | perm::MAP);
                    write!(f, "mem[{:#0x}]:{} = {}", addr, perm, bytes)
                }
            }
            Assignment::Register { name, value } => write!(f, "{} = {:#0x}", name, value),
        }
    }
}

fn check_one<T: Tester>(
    config: &TestConfig,
    tester: &mut T,
    test: &TestCase,
) -> anyhow::Result<()> {
    tracing::debug!("Running test: {:?}", test);
    tester.init(test)?;

    let pcode = tester.check_decode_and_lift(test)?;
    if config.save_pcode {
        save_pcode(config.group, &pcode)?;
    }

    for semantics in &test.semantics {
        tracing::trace!("checking semantics: {:?}", semantics);
        tester.start_at(test.load_addr);
        check_semantics(tester, test.instructions.len() as u64, semantics)
            .map_err(|e| anyhow::format_err!("error on: line {}: {e:#}", semantics.line))?;
    }

    Ok(())
}

fn check_semantics<T: Tester>(
    tester: &mut T,
    instructions: u64,
    semantics: &SemanticsTest,
) -> anyhow::Result<()> {
    for assignment in &semantics.inputs {
        tracing::trace!("writing: {:?}", assignment);
        tester.write_assignment(assignment)?;
    }

    tester.step(instructions)?;

    for assignment in &semantics.outputs {
        tester.check_assignment(assignment)?;
    }

    Ok(())
}

fn save_pcode(name: &str, pcode: &str) -> std::io::Result<()> {
    use std::io::Write;

    let path = Path::new("./tests/pcode").join(name);
    let mut file = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(pcode.as_bytes())?;
    Ok(())
}

fn clear_pcode(name: &str) -> std::io::Result<()> {
    let path = Path::new("./tests/pcode").join(name);
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}
