use pcode::PcodeDisplay;
use sleigh_runtime::{
    Constructor, DecodeAction, LocalIndex, SleighData,
    expr::PatternExprRange,
    semantics::{Export, Local, SemanticAction, Value},
};

fn main() {
    let mut args = std::env::args();
    _ = args.next();

    let path = args.next().expect("expected path to `.slaspec`");
    let parser = match sleigh_parse::Parser::from_path(&path) {
        Ok(parser) => parser,
        Err(err) => panic!("failed to parse `{path}`:\n{err}"),
    };
    let sleigh = match sleigh_compile::build_inner(parser, true) {
        Ok(sleigh) => sleigh,
        Err(err) => panic!("failed to compile `{path}`:\n{err}"),
    };

    for (i, constructor) in sleigh.constructors[..sleigh.constructors.len() - 1].iter().enumerate()
    {
        let constructor_line =
            sleigh.debug_info.constructors.get(i as usize).map_or("unknown", |x| x.line.as_str());

        println!("{constructor_line} {:#?}", ConstructorDebug { sleigh: &sleigh, constructor });
    }

    let mut runtime = sleigh_runtime::Runtime::new(0);
    for arg in args {
        let Some(inst) = parse_hex_string(&arg)
        else {
            eprintln!("Invalid instruction bytes: {arg}");
            continue;
        };

        let Some(decoded) = runtime.decode(&sleigh, 0x0, &inst)
        else {
            eprintln!("Failed to decode {arg}");
            continue;
        };
        let inst = &inst[..decoded.num_bytes() as usize];

        let disasm = runtime.disasm(&sleigh).unwrap_or("<invalid>");
        println!("{inst:02x?} \"{disasm}\"");

        let pcode = match runtime.lift(&sleigh) {
            Ok(pcode) => pcode,
            Err(e) => {
                eprintln!("Error lifting {arg}: {e:?}");
                continue;
            }
        };

        for stmt in &pcode.instructions {
            println!("    {}", stmt.display(&sleigh));
        }
    }
}

fn parse_hex_string(bytes: &str) -> Option<Vec<u8>> {
    let bytes = bytes.trim().as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut out = vec![];
    for pair in bytes.as_chunks::<2>().0 {
        out.push(((pair[0] as char).to_digit(16)? << 8 | (pair[1] as char).to_digit(16)?) as u8);
    }

    Some(out)
}

struct ConstructorDebug<'a> {
    sleigh: &'a SleighData,
    constructor: &'a Constructor,
}

impl std::fmt::Debug for ConstructorDebug<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = self
            .sleigh
            .debug_info
            .subtable_names
            .get(self.constructor.table as usize)
            .unwrap_or(&(0, 0));

        let (decode_start, decode_end) = self.constructor.decode_actions;
        let actions = &self.sleigh.decode_actions[decode_start as usize..decode_end as usize];

        let (decode_start, decode_end) = self.constructor.post_decode_actions;
        let post_actions =
            &self.sleigh.post_decode_actions[decode_start as usize..decode_end as usize];

        let (semantics_start, semantics_end) = self.constructor.semantics;
        let semantics = &self.sleigh.semantics[semantics_start as usize..semantics_end as usize];

        f.debug_struct("Constructor")
            .field(
                "table",
                &format_args!("{} (\"{}\")", self.constructor.table, &self.sleigh.get_str(*name)),
            )
            .field("decode_actions", &DecodeActionList { sleigh: self.sleigh, actions })
            .field("post_decode_actions", &PostDecodeActionList {
                sleigh: self.sleigh,
                actions: &post_actions,
            })
            .field("semantics", &SemanticsList { sleigh: self.sleigh, semantics })
            .field("export", &DebugExport { sleigh: self.sleigh, export: &self.constructor.export })
            .finish()
    }
}

struct DecodeActionList<'a> {
    sleigh: &'a SleighData,
    actions: &'a [DecodeAction],
}

impl std::fmt::Debug for DecodeActionList<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut list = f.debug_list();
        for action in self.actions {
            match action {
                DecodeAction::ModifyContext(field, expr_range) => {
                    let expr = self.sleigh.get_context_mod_expr(*expr_range);
                    list.entry(&format_args!("SetContext({field:?}) = {expr:?}"));
                }
                DecodeAction::Eval(idx, kind) => {
                    list.entry(&format_args!("Field({idx}) = {kind:?}"));
                }
                DecodeAction::Subtable(idx, id) => {
                    list.entry(&format_args!(
                        "Subtable({idx}) = \"{}\"",
                        self.sleigh.get_str(self.sleigh.debug_info.subtable_names[*id as usize])
                    ));
                }
                DecodeAction::NextToken(offset) => {
                    list.entry(&format_args!("NextToken({offset})"));
                }
                other => {
                    list.entry(other);
                }
            }
        }
        list.finish()
    }
}

struct PostDecodeActionList<'a> {
    sleigh: &'a SleighData,
    actions: &'a [(LocalIndex, PatternExprRange)],
}

impl std::fmt::Debug for PostDecodeActionList<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut list = f.debug_list();
        for (idx, expr_range) in self.actions {
            let expr = self.sleigh.get_disasm_expr(*expr_range);
            list.entry(&format_args!("Field({idx:?}) = {expr:?}"));
        }
        list.finish()
    }
}

struct SemanticsList<'a> {
    sleigh: &'a SleighData,
    semantics: &'a [SemanticAction],
}

impl std::fmt::Debug for SemanticsList<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut list = f.debug_list();
        for action in self.semantics {
            match action {
                SemanticAction::Op { op, inputs, output } => {
                    let op = DebugOp { sleigh: self.sleigh, op };
                    let inputs = DebugValueList { sleigh: self.sleigh, values: inputs };
                    match output {
                        Some(out) => list.entry(&format_args!(
                            "{out:?} = {op:?}({inputs:?})",
                            out = DebugValue { sleigh: self.sleigh, value: out }
                        )),
                        None => list.entry(&format_args!("{op:?}({inputs:?})")),
                    };
                }
                SemanticAction::Build(id) => {
                    list.entry(&format_args!("Build Subtable({id})"));
                }
                other => {
                    list.entry(other);
                }
            }
        }
        list.finish()
    }
}

struct DebugOp<'a> {
    sleigh: &'a SleighData,
    op: &'a pcode::Op,
}

impl std::fmt::Debug for DebugOp<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.op {
            pcode::Op::PcodeOp(id) => {
                f.write_str(self.sleigh.get_str(self.sleigh.user_ops[*id as usize]))
            }
            other => other.fmt(f),
        }
    }
}

struct DebugValueList<'a> {
    sleigh: &'a SleighData,
    values: &'a [Value],
}

impl std::fmt::Debug for DebugValueList<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let values = self.values.iter().map(|value| DebugValue { sleigh: self.sleigh, value });
        f.debug_list().entries(values).finish()
    }
}

struct DebugValue<'a> {
    sleigh: &'a SleighData,
    value: &'a Value,
}

impl std::fmt::Debug for DebugValue<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.value.local {
            Local::InstStart => f.write_str("inst_start"),
            Local::InstNext => f.write_str("inst_start"),
            Local::Register(id) => {
                let name = self.sleigh.get_str(self.sleigh.named_registers[id as usize].name);
                f.write_fmt(format_args!("Register({name})"))
            }
            Local::Field(id) => f.write_fmt(format_args!("Field({id})")),
            Local::Subtable(id) => f.write_fmt(format_args!("Subtable({id})")),
            Local::SubtableRef(id) => f.write_fmt(format_args!("SubtableRef({id})")),
            Local::PcodeTmp(id) => f.write_fmt(format_args!("Tmp({id})")),
            Local::Constant(x) => f.write_fmt(format_args!("Const({x:#x})")),
        }?;

        match (self.value.offset, self.value.size) {
            (0, None) => Ok(()),
            (0, Some(size)) => f.write_fmt(format_args!(":{size}")),
            (offset, None) => f.write_fmt(format_args!("+{offset}")),
            (offset, Some(size)) => f.write_fmt(format_args!("+{offset}:{size}")),
        }
    }
}

struct DebugExport<'a> {
    sleigh: &'a SleighData,
    export: &'a Option<Export>,
}

impl std::fmt::Debug for DebugExport<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.export {
            Some(Export::RamRef(value, size)) => {
                f.write_fmt(format_args!("ram[{:?}]:{size}", &DebugValue {
                    sleigh: self.sleigh,
                    value
                }))
            }
            Some(Export::RegisterRef(value, size)) => {
                f.write_fmt(format_args!("register[{:?}]:{size}", &DebugValue {
                    sleigh: self.sleigh,
                    value
                }))
            }
            Some(Export::Value(value)) => DebugValue { sleigh: self.sleigh, value }.fmt(f),
            None => f.write_str("None"),
        }
    }
}
