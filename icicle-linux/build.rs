use std::{
    collections::HashMap,
    io::{BufWriter, Write},
};

const ARCHITECTURES: &[&str] = &["generic", "x64", "i386", "mips", "arm"];

fn main() {
    process_errno_table();

    let tables = ARCHITECTURES
        .iter()
        .map(|arch| {
            println!("cargo:rerun-if-changed=data/syscalls/{arch}.txt");
            std::fs::read_to_string(format!("data/syscalls/{arch}.txt")).unwrap()
        })
        .collect::<Vec<_>>();

    let mut mapper = SyscallMapper::default();
    mapper.add_entry(&SyscallEntry {
        number: None,
        name: "unimplemented",
        handler: SyscallHandler::Path("sys::unimplemented", 0),
    });

    for (arch, table) in ARCHITECTURES.iter().zip(&tables) {
        process_syscall_table(arch, table, &mut mapper);
    }
    build_dispatcher(&mapper.handlers);

    println!("cargo:rerun-if-changed=build.rs");
}

fn output_file(path: impl AsRef<std::path::Path>) -> BufWriter<std::fs::File> {
    let out_dir = std::env::var_os("OUT_DIR").unwrap();
    BufWriter::new(std::fs::File::create(std::path::Path::new(&out_dir).join(path)).unwrap())
}

fn build_dispatcher(syscalls: &[(&str, usize)]) {
    let mut file = output_file("syscall_dispatcher.rs");

    writeln!(file, "match syscall_number {{").unwrap();
    for (i, (path, args)) in syscalls.iter().enumerate() {
        writeln!(file, "    {i} => Handler::_{args}({path}),").unwrap();
    }
    writeln!(file, "    _ => Handler::_0(sys::unimplemented),").unwrap();
    writeln!(file, "}}").unwrap();
}

#[derive(Debug)]
enum SyscallHandler<'a> {
    /// Path to a rust function for handling the syscall with the number of arguments.
    Path(&'a str, usize),
    /// Use the matching generic syscall handler.
    Default,
    /// Use the syscall handler that matches the alias.
    Alias(&'a str),
}

impl<'a> SyscallHandler<'a> {
    fn parse(value: &'a str) -> Option<Self> {
        Some(match value.get(0..1) {
            Some("_") => Self::Default,
            Some("=") => Self::Alias(&value[1..]),
            _ => {
                let (path, rest) = value.split_once('(')?;
                let args = rest.strip_suffix(')')?.parse().ok()?;
                Self::Path(path, args)
            }
        })
    }
}

#[derive(Debug)]
struct SyscallEntry<'a> {
    number: Option<u64>,
    name: &'a str,
    handler: SyscallHandler<'a>,
}

impl<'a> SyscallEntry<'a> {
    fn parse(line: &'a str) -> Option<Self> {
        let line = match line.rfind('#') {
            Some(x) => &line[..x],
            None => line,
        };
        if line.is_empty() {
            return None;
        }

        let (number, line) = line.trim().split_once(char::is_whitespace)?;
        let number = match number {
            "_" => None,
            x => Some(x.parse::<u64>().ok()?),
        };

        let (name, line) = line.trim().split_once(char::is_whitespace)?;
        let handler = SyscallHandler::parse(line.trim())?;

        Some(Self { number, name, handler })
    }
}

#[derive(Default)]
struct SyscallMapper<'a> {
    /// Aliases to the rust handler function. Mapping from `name` -> `handler_id`.
    mapping: HashMap<&'a str, usize>,

    /// Paths to the Rust functions that implement each of the syscalls.
    handlers: Vec<(&'a str, usize)>,
}

impl<'a> SyscallMapper<'a> {
    fn add_entry<'b>(&mut self, entry: &'b SyscallEntry<'a>) -> usize {
        let next = self.handlers.len();
        let id = match entry.handler {
            SyscallHandler::Path(path, args) => *self.mapping.entry(path).or_insert_with(|| {
                self.handlers.push((path, args));
                next
            }),
            SyscallHandler::Default => match self.mapping.get(&entry.name) {
                Some(id) => *id,
                None => panic!("No handler found for: {}", entry.name),
            },
            SyscallHandler::Alias(name) => match self.mapping.get(name) {
                Some(id) => *id,
                None => panic!("No handler found for: {name}"),
            },
        };

        self.mapping.entry(entry.name).or_insert(id);
        id
    }
}

fn process_syscall_table<'a>(arch: &str, table: &'a str, mapper: &mut SyscallMapper<'a>) {
    let mut names_table = output_file(&format!("{arch}_syscall_names.rs"));
    let mut handler_table = output_file(&format!("{arch}_syscall_mapping.rs"));

    writeln!(names_table, "{{\nlet mut t = [\"unknown\"; 600];").unwrap();

    let unimplemented_syscall_id = mapper.mapping.get("unimplemented").unwrap();
    writeln!(handler_table, "{{\nlet mut t = [{unimplemented_syscall_id}; 600];").unwrap();

    for entry in table.lines().filter_map(SyscallEntry::parse) {
        let func = mapper.add_entry(&entry);
        if let Some(number) = entry.number {
            writeln!(&mut names_table, "t[{number}] = \"{}\";", entry.name).unwrap();
            writeln!(&mut handler_table, "t[{number}] = {func};").unwrap();
        }
    }

    writeln!(names_table, "t\n}}").unwrap();
    writeln!(handler_table, "t\n}}").unwrap();
}

fn process_errno_table() {
    use std::fmt::Write;

    // Keep track of errno values that are missing in any architecture so we can generate a warning
    // when they are used.
    let mut missing_errno: HashMap<u64, Vec<String>> = HashMap::new();

    let generic_table = std::fs::read_to_string("data/errno/generic.txt").unwrap();
    let generic = parse_errno_table(&generic_table);

    create_errno_mapping_table("mips", &generic, &mut missing_errno);

    let mut consts = String::new();
    let mut strings = String::new();
    for (name, number) in &generic {
        if let Some(missing) = missing_errno.get(number) {
            writeln!(&mut consts, "#[deprecated(note = \"missing for: {}\")]", missing.join(", "))
                .unwrap();
        }
        writeln!(&mut consts, "pub const {name}: u64 = {number};").unwrap();
        writeln!(&mut strings, "    {number} => \"{name}\",").unwrap();
    }
    strings.push_str("\n    _ => \"EUNKNOWN\",\n");

    let mut out = output_file("errno.rs");
    writeln!(out, "{consts}\n").unwrap();
    writeln!(
        out,
        "pub fn errno_str(errno: u64) -> &'static str {{\n#[allow(unreachable_patterns)]\nmatch errno {{ {strings} }}\n}}",
    ).unwrap();

    println!("cargo:rerun-if-changed=data/errno/generic.txt");
}

fn create_errno_mapping_table(
    arch: &str,
    generic: &[(&str, u64)],
    missing_mapping: &mut HashMap<u64, Vec<String>>,
) {
    let max_errno = generic.iter().map(|(_, id)| id).max().unwrap();

    let table = std::fs::read_to_string(format!("data/errno/{arch}.txt")).unwrap();
    let processed: HashMap<&str, u64> = parse_errno_table(&table).into_iter().collect();

    let mut out = output_file(format!("{arch}_errno.rs"));
    writeln!(out, "{{\nlet mut t = [1; {max_errno}];").unwrap();
    for (name, number) in generic {
        if let Some(mips_number) = processed.get(name) {
            writeln!(&mut out, "t[{number}] = {mips_number};").unwrap();
        }
        else {
            missing_mapping.entry(*number).or_default().push(arch.into());
        }
    }
    writeln!(out, "t}}").unwrap();

    println!("cargo:rerun-if-changed=data/errno/{arch}.txt");
}

fn parse_errno_table(input: &str) -> Vec<(&str, u64)> {
    let mut table = Vec::new();
    for line in input.lines() {
        if line.starts_with('#') || !line.starts_with(char::is_numeric) {
            continue;
        }

        let mut iter = line.split_whitespace();
        let number: u64 = iter.next().unwrap().parse().unwrap();
        let name = iter.next().unwrap();
        table.push((name, number));
        // @todo: read description
    }
    table
}
