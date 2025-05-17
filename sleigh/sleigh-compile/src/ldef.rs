//! Code for loading SLEIGH specifications using ldefs

use std::{
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
};

use serde_derive::Deserialize;
use sleigh_runtime::SleighData;

#[derive(Debug)]
pub enum Error {
    CompileError(String),
    LanguageNotFound(String),
    Io(PathBuf, std::io::Error),
    ParseError(PathBuf, String),
    ContextFieldNotFound(String),
    UnknownRegister(String),
    InvalidPath,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::CompileError(err) => write!(f, "Error compiling slaspec: {err}"),
            Error::LanguageNotFound(name) => write!(f, "No matching language found for: {name}"),
            Error::Io(path, err) => write!(f, "Error reading {}: {err}", path.display()),
            Error::ParseError(path, err) => write!(f, "Error parsing {}: {err}", path.display()),
            Error::UnknownRegister(name) => write!(f, "Unknown register: {name}"),
            Error::ContextFieldNotFound(name) => {
                write!(f, "Failed to find context field: '{name}'")
            }
            Error::InvalidPath => write!(f, "Path to ldef file was invalid"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Default)]
pub struct CallingCov {
    /// Varnodes of integer arguments for the calling convention.
    pub int_args: Vec<pcode::VarNode>,
    /// Varnodes for floating args for the calling convention.
    pub float_args: Vec<pcode::VarNode>,
    /// Registers left unmodified after executing the function.
    pub unaffected: Vec<pcode::VarNode>,
    /// Varnodes used to hold integer return values. (INVALID if not used)
    pub int_return: pcode::VarNode,
    /// Varnodes used to hold floating point return values. (INVALID if not used)
    pub float_return: pcode::VarNode,
}

pub struct SleighLanguage {
    /// Processor name.
    pub processor: String,
    /// Endianness of the processor.
    pub endian: Endianness,
    /// Address size (in bits) of the processor.
    pub size: u32,
    /// Name of the compiler defined to the language.
    pub compiler: Option<String>,
    /// The parsed SLEIGH specification.
    pub sleigh: SleighData,
    /// The initial value of the context register.
    pub initial_ctx: u64,
    /// Varnode containing the program counter.
    pub pc: pcode::VarNode,
    /// Varnode containing the stack pointer (invalid if unknown).
    pub sp: pcode::VarNode,
    /// The default calling convention.
    pub default_calling_cov: CallingCov,
}

pub fn build(
    ldef_path: &Path,
    lang_id: &str,
    cspec_id: Option<&str>,
    verbose: bool,
) -> Result<SleighLanguage, Error> {
    let mut builder = SleighLanguageBuilder::new(ldef_path, lang_id).set_verbose(verbose);
    if let Some(cspec_id) = cspec_id {
        builder = builder.set_cspec_id(cspec_id)
    }
    builder.build()
}

pub struct SleighLanguageBuilder {
    pub ldef_path: PathBuf,
    pub lang_id: String,
    pub cspec_id: Option<String>,
    pub verbose: bool,
    pub defines: Vec<String>,
}

impl SleighLanguageBuilder {
    pub fn new(ldef_path: impl Into<PathBuf>, lang_id: impl Into<String>) -> Self {
        Self {
            ldef_path: ldef_path.into(),
            lang_id: lang_id.into(),
            cspec_id: None,
            verbose: false,
            defines: vec!["ICICLE".into()],
        }
    }

    pub fn set_cspec_id(mut self, cspec_id: impl Into<String>) -> Self {
        self.cspec_id = Some(cspec_id.into());
        self
    }

    pub fn set_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    pub fn clear_defines(mut self) -> Self {
        self.defines.clear();
        self
    }

    pub fn define(mut self, define: impl Into<String>) -> Self {
        self.defines.push(define.into());
        self
    }

    pub fn build(self) -> Result<SleighLanguage, Error> {
        build_inner(self)
    }
}

fn build_inner(
    SleighLanguageBuilder { ldef_path, lang_id, cspec_id, verbose, defines }: SleighLanguageBuilder,
) -> Result<SleighLanguage, Error> {
    let ldef = LanguageDef::from_xml(&ldef_path)?;
    let language =
        ldef.find_match(&lang_id).ok_or_else(|| Error::LanguageNotFound(lang_id.clone()))?;

    let pspec_path = language.pspec_path(&ldef_path).ok_or(Error::InvalidPath)?;
    let pspec: PSpec = serde_xml_rs::from_reader(BufReader::new(
        File::open(&pspec_path).map_err(|err| Error::Io(pspec_path.clone(), err))?,
    ))
    .map_err(|err| Error::ParseError(pspec_path, err.to_string()))?;

    let slaspec_path = language.slaspec_path(&ldef_path).ok_or(Error::InvalidPath)?;

    let root = slaspec_path.parent().ok_or(Error::InvalidPath)?;
    let initial_file =
        slaspec_path.file_name().and_then(|x| x.to_str()).ok_or(Error::InvalidPath)?;

    let input_source = sleigh_parse::FileLoader::new(root.to_owned());

    let mut parser = sleigh_parse::Parser::new(input_source, &defines);
    if let Err(err) = parser.include_file(initial_file) {
        return Err(Error::ParseError(slaspec_path, parser.error_formatter(err).to_string()));
    }
    let sleigh = crate::build_inner(parser, verbose).map_err(Error::CompileError)?;

    // Resolve the initial context using information from `context_data` in the processor
    // specification.
    let mut initial_ctx = 0_u64;
    if let Some(context_set) = pspec.context_data.context_set {
        for entry in &context_set.set {
            let field = sleigh
                .get_context_field(&entry.name)
                .ok_or_else(|| Error::ContextFieldNotFound(entry.name.clone()))?;
            field.field.set(&mut initial_ctx, entry.val as i64);
        }
    }

    let get_reg = |name: &str| {
        sleigh.get_varnode(name).ok_or_else(|| Error::UnknownRegister(name.to_string()))
    };

    let pc = get_reg(&pspec.programcounter.register)?;

    let mut sp = pcode::VarNode::NONE;

    let mut default_calling_cov = CallingCov::default();

    let mut compiler = None;
    if let Some((name, path)) = language.cspec_path(&ldef_path, cspec_id.as_deref()) {
        compiler = Some(name);

        // If we have a compiler spec, we can obtain additional information about the target
        // specification.
        let cspec: CSpec = serde_xml_rs::from_reader(BufReader::new(
            File::open(&path).map_err(|err| Error::Io(path.clone(), err))?,
        ))
        .map_err(|err| Error::ParseError(path, err.to_string()))?;
        sp = get_reg(&cspec.stackpointer.register)?;

        if let Some(proto) = cspec.default_proto {
            default_calling_cov = map_calling_cov(proto.prototype, get_reg)?;
        }
    }
    else {
        // Try to set some reasonable defaults if no compiler is specified.
        if let Some(expected_sp) =
            sleigh.named_registers.iter().find(|x| matches!(sleigh.get_str(x.name), "sp" | "SP"))
        {
            sp = expected_sp.get_var().unwrap();
        }
    }

    Ok(SleighLanguage {
        processor: language.processor.clone(),
        endian: language.endian,
        size: language.size,
        compiler,
        sleigh,
        initial_ctx,
        pc,
        sp,
        default_calling_cov,
    })
}

fn map_calling_cov(
    proto: Prototype,
    get_reg: impl Fn(&str) -> Result<pcode::VarNode, Error>,
) -> Result<CallingCov, Error> {
    let mut cov = CallingCov::default();
    for input in proto.input.pentry {
        match input.location {
            Location::Register(reg) => {
                let reg = get_reg(&reg.name)?;
                match input.metatype {
                    MetaType::Int => cov.int_args.push(reg),
                    MetaType::Float => cov.float_args.push(reg),
                }
            }
            // Non-register locations ignored for now.
            _ => {}
        }
    }

    for output in proto.output.pentry {
        match output.location {
            Location::Register(reg) => {
                let reg = get_reg(&reg.name)?;
                match output.metatype {
                    MetaType::Int => cov.int_return = reg,
                    MetaType::Float => cov.float_return = reg,
                }
            }
            // Non-register locations ignored for now.
            _ => {}
        }
    }

    for location in proto.unaffected.location {
        match location {
            Location::Register(reg) => {
                cov.unaffected.push(get_reg(&reg.name)?);
            }
            // Non-register locations ignored for now.
            _ => {}
        }
    }

    Ok(cov)
}

#[derive(Debug, Deserialize)]
struct Set {
    pub name: String,
    pub val: u64,
}

#[derive(Debug, Deserialize)]
struct ProgramCounter {
    register: String,
}

#[allow(unused)]
#[derive(Debug, Deserialize)]
struct ContextSet {
    pub space: String,
    #[serde(rename = "$value")]
    pub set: Vec<Set>,
}

#[allow(unused)]
#[derive(Debug, Default, Deserialize)]
struct ContextData {
    context_set: Option<ContextSet>,
    #[serde(skip)]
    tracked_set: Vec<()>,
}

/// A SLEIGH processor specification file
#[derive(Debug, Deserialize)]
struct PSpec {
    #[allow(unused)]
    #[serde(skip)]
    properties: Vec<()>,
    programcounter: ProgramCounter,
    #[serde(default)]
    context_data: ContextData,
    #[allow(unused)]
    #[serde(skip)]
    register_data: Vec<()>,
}

#[derive(Debug, Deserialize)]
struct StackPointer {
    register: String,
    #[allow(unused)]
    space: String,
}

#[derive(Default, Debug, Deserialize)]
enum MetaType {
    #[default]
    #[serde(rename = "int")]
    Int,
    #[serde(rename = "float")]
    Float,
}

#[derive(Debug, Deserialize)]
struct RegisterDesc {
    name: String,
}

#[allow(unused)]
#[derive(Debug, Deserialize)]
struct AddrDesc {
    space: String,
}

#[allow(unused)]
#[derive(Debug, Deserialize)]
struct VarnodeDesc {
    space: String,
    offset: u64,
    size: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Location {
    Register(RegisterDesc),
    #[allow(unused)]
    VarNode(VarnodeDesc),
    #[allow(unused)]
    Addr(AddrDesc),
}

#[derive(Debug, Deserialize)]
struct Pentry {
    #[allow(unused)]
    minsize: u32,
    #[allow(unused)]
    maxsize: u32,
    #[serde(default)]
    metatype: MetaType,
    #[serde(rename = "$value")]
    location: Location,
}

#[derive(Debug, Deserialize)]
struct EntryList {
    pentry: Vec<Pentry>,
}

#[derive(Debug, Default, Deserialize)]
pub struct LocationList {
    #[serde(rename = "$value")]
    location: Vec<Location>,
}

#[derive(Debug, Deserialize)]
struct Prototype {
    input: EntryList,
    #[allow(unused)]
    output: EntryList,
    #[serde(default)]
    unaffected: LocationList,
}

#[derive(Debug, Deserialize)]
struct DefaultProto {
    prototype: Prototype,
}

/// A SLEIGH compiler specification file
#[derive(Debug, Deserialize)]
pub struct CSpec {
    default_proto: Option<DefaultProto>,
    #[allow(unused)]
    returnaddress: Option<Location>,
    stackpointer: StackPointer,
}

/// A SLEIGH language definition file.
#[derive(Debug, Deserialize)]
pub struct LanguageDef {
    pub language: Vec<LanguageDesc>,
}

impl LanguageDef {
    pub fn from_xml(path: &Path) -> Result<Self, Error> {
        serde_xml_rs::from_reader(BufReader::new(
            File::open(path).map_err(|err| Error::Io(path.into(), err))?,
        ))
        .map_err(|err| Error::ParseError(path.into(), err.to_string()))
    }

    // Find the language definition that best matches `id`. Prefer exact matches first, then matches
    // with a default suffix match, then falling back to first prefix match.
    pub fn find_match(&self, id: &str) -> Option<&LanguageDesc> {
        let mut first_default_match = None;
        let mut first_prefix_match = None;

        for lang in &self.language {
            if lang.id == id {
                return Some(lang);
            }

            if lang.id.starts_with(id) {
                if first_default_match.is_none() && lang.variant == "default" {
                    first_default_match = Some(lang);
                }
                if first_prefix_match.is_none() {
                    first_prefix_match = Some(lang);
                }
            }
        }

        if first_default_match.is_some() {
            return first_default_match;
        }
        first_prefix_match
    }
}

#[derive(Debug, Deserialize)]
pub struct CompilerDesc {
    pub name: String,
    pub spec: String,
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub struct LanguageDesc {
    pub id: String,
    pub processor: String,
    pub endian: Endianness,
    pub size: u32,
    pub variant: String,
    pub version: String,
    pub slafile: String,
    pub processorspec: String,
    pub description: String,
    pub compiler: Vec<CompilerDesc>,
}

impl LanguageDesc {
    pub fn pspec_path(&self, ldef_path: &Path) -> Option<PathBuf> {
        let root = ldef_path.parent()?;
        Some(root.join(&self.processorspec))
    }

    pub fn slaspec_path(&self, ldef_path: &Path) -> Option<PathBuf> {
        let root = ldef_path.parent()?;
        let filename = self.slafile.strip_suffix(".sla").unwrap_or(&self.slafile);
        Some(root.join(format!("{filename}.slaspec")))
    }

    pub fn cspec_path(
        &self,
        ldef_path: &Path,
        compiler_id: Option<&str>,
    ) -> Option<(String, PathBuf)> {
        let root = ldef_path.parent()?;
        let get_path = |compiler: &CompilerDesc| (compiler.id.clone(), root.join(&compiler.spec));

        if let Some(id) = compiler_id {
            return Some(get_path(self.compiler.iter().find(|x| x.id == id)?));
        }

        // No compiler specified, see if the specification contains a default compiler.
        if let Some(compiler) =
            self.compiler.iter().find(|x| x.id == "default" || x.name == "default")
        {
            return Some(get_path(compiler));
        }

        // Otherwise just try to use gcc if available
        if let Some(compiler) = self.compiler.iter().find(|x| x.id == "gcc" || x.name == "gcc") {
            return Some(get_path(compiler));
        }

        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Endianness {
    Little,
    Big,
}
