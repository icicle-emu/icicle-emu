use std::{collections::HashMap, path::Path};

use sleigh_parse::{ast, Parser};
use sleigh_runtime::{
    matcher::Matcher, AttachmentIndex, Constructor, ConstructorDebugInfo, DecodeAction,
    DisplaySegment, NamedRegister, RegisterAlias, RegisterAttachment, SleighData, StrIndex,
};

pub use sleigh_parse::resolve_dependencies;

use crate::symbols::SymbolTable;

mod constructor;
mod matcher;
mod symbols;

pub fn from_path(sleigh_spec: impl AsRef<Path>) -> Result<SleighData, String> {
    build_inner(Parser::from_path(sleigh_spec.as_ref())?, false)
}

pub fn from_data(root: &str, data: HashMap<String, String>) -> Result<SleighData, String> {
    build_inner(Parser::from_data(root, data)?, false)
}

pub fn build_inner(mut parser: Parser, verbose: bool) -> Result<SleighData, String> {
    let ast = match parser.parse::<ast::Sleigh>() {
        Ok(ast) => ast,
        Err(e) => return Err(format!("{}", parser.error_formatter(e))),
    };

    let mut symbols = SymbolTable::new(parser);
    let mut ctx = Context::default();
    ctx.verbose = verbose;
    // @todo: make configurable
    ctx.capture_debug_info = true;
    ctx.data.alignment = 1;

    for item in ast.items {
        resolve_item(&mut ctx, &mut symbols, item)?;
    }

    ctx.data.default_space_size =
        symbols.default_space.map(|i| symbols.spaces[i as usize].size).unwrap_or(8);

    for entry in &symbols.context_fields {
        ctx.data
            .context_fields
            .push(sleigh_runtime::ContextField { field: entry.field, flow: entry.flow });
    }

    for constructor in &symbols.constructors {
        add_constructor(constructor, &mut ctx, &symbols);
    }

    for table in &symbols.tables {
        let matcher = matcher::build_sequential_matcher(&symbols, table, &ctx)?;
        ctx.data.matchers.push(Matcher::SequentialMatcher(matcher));
    }

    ctx.data.named_registers = vec![NamedRegister::default(); symbols.registers.len()];

    // Reserve register 0 to use for invalid varnodes.
    let invalid = ctx.add_string("INVALID_VARNODE");
    ctx.data.registers.push(sleigh_runtime::RegisterInfo {
        name: invalid,
        size: 0,
        offset: u32::MAX,
        aliases: vec![],
    });

    // Map overlapping varnodes.
    let mut registers: Vec<_> = symbols.registers.into_iter().enumerate().collect();
    registers.sort_by_key(|(_, reg)| (std::cmp::Reverse(reg.size), reg.offset));
    for (idx, reg) in registers {
        let name_str = symbols.parser.get_ident_str(reg.name);
        ctx.data.register_name_mapping.insert(name_str.to_string(), idx as u32);

        let mut name = ctx.add_string(name_str);

        // Check if there is an existing mapping for this register, if so add it as an alias.
        if let Some(&(id, byte_offset)) = ctx.data.register_mapping.get(&reg.offset) {
            let alias = RegisterAlias { offset: byte_offset as u16, size: reg.size, name };
            ctx.data.registers[id as usize].aliases.push(alias);

            ctx.data.named_registers[idx] = NamedRegister {
                name,
                var: pcode::VarNode::new(id, 16).slice(byte_offset, reg.size.min(16) as u8),
                offset: reg.offset,
            };
            continue;
        }

        let reg_id = ctx.data.registers.len().try_into().unwrap();
        ctx.data.named_registers[idx] = NamedRegister {
            name,
            var: pcode::VarNode::new(reg_id, reg.size.min(16) as u8),
            offset: reg.offset,
        };

        // We only support operating on registers that are at most 128-bits. This is only an issue
        // when dealing with vector operations (e.g. AVX, NEON). To handle this we need to split the
        // register into multiple registers.
        for i in (0..reg.size).step_by(16) {
            let reg_id = ctx.data.registers.len().try_into().unwrap();
            let offset = reg.offset + i as u32;
            let size = std::cmp::min(reg.size - i, 16) as u8;

            if i != 0 {
                name = ctx.add_string(&format!("{}_{}", name_str, i));
            }

            ctx.data.registers.push(sleigh_runtime::RegisterInfo {
                name,
                size,
                offset,
                aliases: vec![],
            });

            for byte in 0..size {
                let varnode_offset = offset + byte as u32;
                ctx.data.register_mapping.insert(varnode_offset, (reg_id, byte as u8));
            }
        }
    }

    // Register additional varnodes for saved temporaries
    for i in 0..8 {
        let var = ctx
            .data
            .add_custom_reg(&format!("$tmp{i}"), 16)
            .ok_or_else(|| format!("failed to reserve varnode for temporary"))?;
        ctx.data.saved_tmps.push(var);
    }

    for attachment in &symbols.attachments {
        match attachment {
            symbols::Attachment::Register(regs, size) => {
                let start = ctx.data.attached_registers.len() as u32;
                for &entry in regs {
                    let reg = entry.map(|id| {
                        let reg = &ctx.data.named_registers[id as usize];
                        RegisterAttachment { name: reg.name, offset: reg.offset }
                    });
                    ctx.data.attached_registers.push(reg);
                }
                let end = ctx.data.attached_registers.len() as u32;

                let size = size.unwrap_or(ctx.data.default_space_size as u16);
                ctx.data
                    .attachments
                    .push(AttachmentIndex::Register((start, end), size.try_into().unwrap()));
            }
            symbols::Attachment::Name(names) => {
                let start = ctx.data.attached_names.len() as u32;
                for name in names {
                    let (start, end) = ctx.add_string(name);
                    ctx.data.attached_names.push((start, end));
                }
                let end = ctx.data.attached_names.len() as u32;
                ctx.data.attachments.push(AttachmentIndex::Name((start, end)));
            }
            symbols::Attachment::Value(values) => {
                let start = ctx.data.attached_values.len() as u32;
                ctx.data.attached_values.extend(values.iter().map(|v| *v as i64));
                let end = ctx.data.attached_values.len() as u32;
                ctx.data.attachments.push(AttachmentIndex::Value((start, end)));
            }
        }
    }

    for userop in &symbols.user_ops {
        let (start, end) = ctx.add_string(symbols.parser.get_ident_str(*userop));
        ctx.data.user_ops.push((start, end));
    }

    Ok(ctx.data)
}

#[derive(Default)]
pub(crate) struct Context {
    data: SleighData,
    cache: SleighDataCache,

    has_endian: bool,
    has_alignment: bool,
    has_register_space: bool,
    has_ram_space: bool,

    verbose: bool,
    capture_debug_info: bool,
    with: Vec<ast::WithDef>,
}

impl Context {
    pub fn add_string(&mut self, s: &str) -> StrIndex {
        self.cache.add_string(s, &mut self.data)
    }
}

fn resolve_item(ctx: &mut Context, syms: &mut SymbolTable, item: ast::Item) -> Result<(), String> {
    // Macro for checking and returning error if a field has already been defined
    macro_rules! check_not_defined {
        ($field:expr, $msg:expr) => {{
            if $field {
                return Err($msg.into());
            }
            $field = true;
        }};
    }

    match item {
        ast::Item::DefineEndian(kind) => {
            check_not_defined!(ctx.has_endian, "duplicate endian definition");
            ctx.data.big_endian = kind == ast::EndianKind::Big;
        }
        ast::Item::DefineAlignment(bytes) => {
            check_not_defined!(ctx.has_alignment, "duplicate alignment definition");
            ctx.data.alignment = bytes.try_into().map_err(|_| "alignment too large")?;
        }
        ast::Item::DefineSpace(space) => {
            match space.kind {
                ast::SpaceKind::RegisterSpace => {
                    if space.default {
                        return Err("Register space cannot be used as the default space".into());
                    }
                    if space.word_size.is_some() {
                        return Err("Register space cannot have a word size".into());
                    }
                    check_not_defined!(
                        ctx.has_register_space,
                        "multiple register spaces not supported"
                    );

                    // Size is the only parameter that can change for register spaces (and I'm not
                    // currently sure what they do)
                    syms.define_space(space)?;
                }

                ast::SpaceKind::RamSpace => {
                    check_not_defined!(ctx.has_ram_space, "multiple ram spaces not supported");
                    syms.define_space(space)?;
                }
                ast::SpaceKind::RomSpace => return Err("rom space not implemented".into()),
            };
        }
        ast::Item::SpaceNameDef(def) => syms.define_register_names(def)?,
        ast::Item::DefineBitRange(entries) => {
            for entry in entries {
                syms.define_bitrange(entry)?;
            }
        }
        ast::Item::DefineContext(def) => syms.define_context(def)?,
        ast::Item::DefineToken(def) => syms.define_token(def)?,
        ast::Item::DefineUserOp(op) => syms.define_userop(op)?,
        ast::Item::AttachVariables(attach) => syms.attach_variables(attach)?,
        ast::Item::AttachNames(attach) => {
            syms.define_attachment(symbols::Attachment::Name(attach.names), &attach.fields)?
        }
        ast::Item::AttachValues(attach) => {
            syms.define_attachment(symbols::Attachment::Value(attach.values), &attach.fields)?
        }
        ast::Item::Macro(def) => syms.define_macro(def)?,
        ast::Item::Constructor(mut constructor) => {
            for with in ctx.with.iter().rev() {
                constructor.table = match (with.table, constructor.table) {
                    (Some(with), Some(constructor)) => {
                        let name = format!(
                            "{}{}",
                            syms.parser.get_ident_str(with),
                            syms.parser.get_ident_str(constructor)
                        );
                        Some(syms.parser.get_ident(&name))
                    }
                    (Some(with), None) => Some(with.clone()),
                    (None, constructor) => constructor,
                };

                if !with.disasm_actions.is_empty() {
                    constructor.disasm_actions = with
                        .disasm_actions
                        .iter()
                        .cloned()
                        .chain(constructor.disasm_actions.into_iter())
                        .collect();
                }

                constructor.constraint = ast::ConstraintExpr::Op(
                    Box::new(with.constraint.clone()),
                    ast::ConstraintOp::And,
                    Box::new(constructor.constraint),
                );
            }

            if let Err(e) = syms.define_constructor(ctx, &constructor) {
                if ctx.verbose {
                    eprintln!("[WARNING] {}", e);
                }
            }
        }
        ast::Item::With(mut def) => {
            let items = std::mem::take(&mut def.items);
            ctx.with.push(def);
            for item in items {
                resolve_item(ctx, syms, item)?;
            }
            ctx.with.pop();
        }
    }

    Ok(())
}

fn add_constructor(
    constructor: &constructor::Constructor,
    ctx: &mut Context,
    symbols: &SymbolTable,
) {
    let mut mnemonic = None;
    if let Some(value) = constructor.mnemonic.as_ref() {
        mnemonic = Some(ctx.cache.add_string(value, &mut ctx.data));
    }

    let fields_start = ctx.data.fields.len() as u32;
    for field in &constructor.fields {
        ctx.data.fields.push(field.clone());
    }
    let fields_end = ctx.data.fields.len() as u32;

    let decode_actions_start = ctx.data.decode_actions.len() as u32;
    for (field, expr) in &constructor.disasm_actions.context_mod {
        let start = ctx.data.context_disasm_expr.len() as u32;
        ctx.data.context_disasm_expr.extend_from_slice(expr);
        let end = ctx.data.context_disasm_expr.len() as u32;
        let field = symbols.context_fields[*field as usize].field.into();
        ctx.data.decode_actions.push(DecodeAction::ModifyContext(field, (start, end)));
    }

    for field in &constructor.disasm_actions.global_set {
        let field = symbols.context_fields[*field as usize].field.into();
        ctx.data.decode_actions.push(DecodeAction::SaveContext(field));
    }

    for action in &constructor.decode_actions {
        ctx.data.decode_actions.push(action.clone());
    }
    let decode_actions_end = ctx.data.decode_actions.len() as u32;

    let post_decode_actions_start = ctx.data.post_decode_actions.len() as u32;
    for (field, expr) in &constructor.disasm_actions.fields {
        let start = ctx.data.disasm_exprs.len() as u32;
        ctx.data.disasm_exprs.extend_from_slice(expr);
        let end = ctx.data.disasm_exprs.len() as u32;
        ctx.data.post_decode_actions.push((*field as u32, (start, end)));
    }
    let post_decode_actions_end = ctx.data.post_decode_actions.len() as u32;

    let semantics_start = ctx.data.semantics.len() as u32;
    for action in &constructor.semantics.actions {
        // @todo?: experiment to determine whether it is worth deduplicating the actions (I think
        // this is unlikely).
        ctx.data.semantics.push(action.clone());
    }
    let semantics_end = ctx.data.semantics.len() as u32;

    ctx.data.constructors.push(Constructor {
        table: constructor.table,
        mnemonic,
        fields: (fields_start, fields_end),
        decode_actions: (decode_actions_start, decode_actions_end),
        post_decode_actions: (post_decode_actions_start, post_decode_actions_end),
        subtables: constructor.subtables.len() as u32,
        display: constructor.display,
        semantics: (semantics_start, semantics_end),
        delay_slot: constructor.has_delay_slot(),
        export: constructor.semantics.export,
        temporaries: constructor.semantics.temporaries as u32,
    });

    if ctx.capture_debug_info {
        let info = ConstructorDebugInfo { line: symbols.format_span(&constructor.span) };
        ctx.data.debug_info.constructors.push(info);
    }
}

#[derive(Default)]
pub(crate) struct SleighDataCache {
    pub strings_map: HashMap<String, StrIndex>,
    pub display_map: HashMap<Vec<DisplaySegment>, (u32, u32)>,
}

impl SleighDataCache {
    fn add_string(&mut self, string: &str, data: &mut SleighData) -> StrIndex {
        if let Some(index) = self.strings_map.get(string) {
            return *index;
        }

        let index = data.add_string(string);
        self.strings_map.insert(string.to_owned(), index);
        index
    }

    fn add_display_segment(
        &mut self,
        segment: &[DisplaySegment],
        data: &mut SleighData,
    ) -> (u32, u32) {
        if let Some(index) = self.display_map.get(segment) {
            return *index;
        }

        let (start, end) = data.add_display_segments(segment);
        self.display_map.insert(segment.to_vec(), (start, end));
        (start, end)
    }
}

#[test]
fn backtracking() {
    const INSTRUCTIONS: &[(u32, &str)] = &[
        // shift 1
        (0x080021e2, "eor r0,r1,#0x8"),
        (0x010c21e2, "eor r0,r1,#0x100"),

        // shift 2
        (0x020021e0, "eor r0,r1,r2"),
        (0x220021e0, "eor r0,r1,r2, lsr #32"),
    ];

    let ghidra_home = std::env::var("GHIDRA_SRC").unwrap();
    let file = format!(
        "{}/Ghidra/Processors/ARM/data/languages/ARM4_le.slaspec",
        ghidra_home
    );
    let sleigh = from_path(&file).unwrap();
    for (token, result) in INSTRUCTIONS.iter() {
        println!("try to decode {}", result);
        let mut decoder = sleigh_runtime::Decoder::new();
        decoder.set_inst(0, &token.to_be_bytes());
        let instruction = sleigh.decode(&mut decoder).unwrap();
        let output = sleigh.disasm(&instruction).unwrap();

        assert_eq!(&output, result);
    }
}
