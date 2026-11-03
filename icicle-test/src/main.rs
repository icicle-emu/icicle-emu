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

    match run() {
        Ok(true) => std::process::exit(1),
        Ok(false) => {}
        Err(e) => {
            eprintln!("{:#}", e);
            std::process::exit(1);
        }
    }
}

enum TestMode {
    All,
    AllNoOpt,
    One(String, String),
    Trace(String, String),
    TraceNoOpt(String, String),
    Bench(String, String),
}

fn get_arch_and_target() -> anyhow::Result<(String, String)> {
    let arch = std::env::args().nth(2).context("Expected architecture name")?;
    let test = std::env::args().nth(3).context("Expected test file")?;
    Ok((arch, test))
}

fn run() -> anyhow::Result<bool> {
    let mode_str = std::env::args().nth(1);
    let mode = match mode_str.as_deref() {
        Some("all") => TestMode::All,
        Some("all-no-opt") => TestMode::AllNoOpt,
        Some("bench") => {
            let (arch, target) = get_arch_and_target()?;
            TestMode::Bench(arch, target)
        }
        Some("trace") => {
            let (arch, test) = get_arch_and_target()?;
            TestMode::Trace(arch, test)
        }
        Some("trace-no-opt") => {
            let (arch, test) = get_arch_and_target()?;
            TestMode::TraceNoOpt(arch, test)
        }
        Some(arch) => {
            let test =
                std::env::args().nth(2).ok_or_else(|| anyhow::format_err!("Expected test file"))?;
            TestMode::One(arch.to_owned(), test)
        }
        _ => TestMode::All,
    };

    const ALL_TESTS: &[(&str, &[&str])] = &[
        ("x86_64", &["x64"]),
        ("i386", &["x86"]),
        ("mipsel", &["mipsel"]),
        ("mips", &["mips"]),
        ("riscv64", &["riscv64gc"]),
        ("riscv32", &["riscv32gc"]),
        ("msp430", &["msp430x"]),
        ("arm", &["arm"]),
        ("aarch64", &["aarch64"]),
        ("powerpc", &["powerpc"]),
        ("m68k", &["m68k"]),
    ];

    let mut results = Results::default();
    match mode {
        TestMode::All => {
            let cfg = TestConfig::default();
            for (target, tests) in ALL_TESTS {
                results += configure_and_run(target, &cfg, tests)?;
            }
        }
        TestMode::AllNoOpt => {
            let cfg = TestConfig { optimize: false, ..TestConfig::default() };
            for (target, tests) in ALL_TESTS {
                results += configure_and_run(target, &cfg, tests)?;
            }
        }
        TestMode::Bench(arch, target) => {
            // Current bench results:
            //  - (debug)   0.3566 s / iter, 0.0944 ms / inst
            //  - (release) 0.0226 s / iter, 0.0060 ms / inst
            run_bench(&arch, &target)?;
        }
        TestMode::One(name, test) => {
            results += configure_and_run(&name, &TestConfig::default(), &[&test])?;
        }
        TestMode::Trace(name, test) => {
            let cfg = TestConfig {
                save_pcode: true,
                trace: true,
                optimize: true,
                dump_il: true,
                ..TestConfig::default()
            };
            results += configure_and_run(&name, &cfg, &[&test])?;
        }
        TestMode::TraceNoOpt(name, test) => {
            let cfg = TestConfig {
                save_pcode: true,
                trace: true,
                optimize: false,
                dump_il: true,
                ..TestConfig::default()
            };
            results += configure_and_run(&name, &cfg, &[&test])?;
        }
    }

    println!("\n{} tests {} errors {} ignored", results.count, results.errors, results.skip);

    Ok(results.errors != 0)
}

fn configure_and_run(
    triple_str: &str,
    config: &TestConfig,
    tests: &[&str],
) -> anyhow::Result<Results> {
    let triple: target_lexicon::Triple =
        triple_str.parse().map_err(|_| anyhow::format_err!("Unknown target: {triple_str}"))?;

    let disable_jit = std::env::var("ICICLE_DISABLE_JIT").is_ok();
    let cpu_config = icicle_vm::cpu::Config {
        triple,
        enable_jit: !disable_jit,
        optimize_instructions: config.optimize,
        optimize_block: config.optimize,
        shadow_stack: icicle_vm::cpu::ShadowStackState::Disabled,
        ..Default::default()
    };

    let mut vm = icicle_vm::build(&cpu_config)
        .map_err(|e| anyhow::format_err!("Failed to build {triple_str}: {e}"))?;

    if config.dump_il {
        vm.jit.il_dump = Some(String::new());
    }
    // vm.cpu.mem.detect_self_modifying_code = false;

    let result =
        match std::panic::catch_unwind::<_, anyhow::Result<_>>(std::panic::AssertUnwindSafe(|| {
            run_test_and_print(&mut vm, &config, tests)
        })) {
            Ok(result) => result,
            Err(e) => Err(anyhow::format_err!("Internal emulator panic: {:?}", e)),
        };

    if let Some(il_dump) = &vm.jit.il_dump {
        std::fs::write("translated.clif", il_dump).unwrap();
    }

    result
}

fn run_bench(triple: &str, test: &str) -> anyhow::Result<()> {
    let path = Path::new("./tests").join(&format!("{test}.ins"));
    let input = std::fs::read_to_string(&path)
        .with_context(|| anyhow::format_err!("Failed to load: {}", path.display()))?;
    let mut parser = parser::Parser::new(&input);

    let triple: target_lexicon::Triple =
        triple.parse().map_err(|_| anyhow::format_err!("Unknown target: {}", triple))?;

    let lang = icicle_vm::sleigh_init(&triple)?;
    let mut source = icicle_vm::cpu::utils::BasicInstructionSource::new(lang.sleigh);
    let mut lifter = icicle_vm::cpu::lifter::InstructionLifter::new();
    lifter.set_context(lang.initial_ctx);

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
                .map_err(|e| anyhow::format_err!("Failed to lift: {:#x}: {e:?}", test.load_addr))?;
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

#[derive(Default)]
struct Results {
    count: usize,
    skip: usize,
    errors: usize,
}

impl std::ops::AddAssign for Results {
    fn add_assign(&mut self, rhs: Self) {
        self.count += rhs.count;
        self.skip += rhs.skip;
        self.errors += rhs.errors;
    }
}

fn run_test_and_print<T: Tester>(
    tester: &mut T,
    config: &TestConfig,
    tests: &[&str],
) -> anyhow::Result<Results> {
    let mut results = Results::default();
    for test in tests {
        let (count, skip, errors) = run_test(tester, test, config.save_pcode)?;
        results.count += count;
        results.skip += skip;
        results.errors += errors.len();
        eprintln!("{test}.ins: {count} tests, {skip} skipped, {} errors", errors.len());
        for error in errors {
            eprintln!("\t{}", error);
        }
    }
    Ok(results)
}

#[derive(Clone)]
struct TestConfig {
    save_pcode: bool,
    #[allow(dead_code)]
    dump_il: bool,
    #[allow(dead_code)]
    trace: bool,
    optimize: bool,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self { optimize: true, save_pcode: true, dump_il: false, trace: false }
    }
}

fn run_test<T: Tester>(
    tester: &mut T,
    name: &str,
    save_pcode: bool,
) -> anyhow::Result<(usize, usize, Vec<String>)> {
    let mut writer = match save_pcode {
        true => {
            let path = Path::new("./tests/pcode").join(name);
            Some(std::io::BufWriter::new(
                std::fs::OpenOptions::new().create(true).write(true).truncate(true).open(path)?,
            ))
        }
        false => None,
    };

    let path = Path::new("./tests").join(&format!("{name}.ins"));
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

        if let Err(e) = check_one(tester, &test_case, writer.as_mut()) {
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

fn check_one<T: Tester, W: std::io::Write>(
    tester: &mut T,
    test: &TestCase,
    output: Option<&mut W>,
) -> anyhow::Result<()> {
    tracing::debug!("Running test: {:?}", test);
    tester.init(test)?;

    let pcode = tester.check_decode_and_lift(test)?;
    if let Some(output) = output {
        save_pcode(output, &pcode)?;
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

fn save_pcode<W: std::io::Write>(mut writer: W, pcode: &str) -> std::io::Result<()> {
    writer.write_all(pcode.as_bytes())?;
    Ok(())
}
