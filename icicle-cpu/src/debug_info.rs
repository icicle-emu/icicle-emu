use std::{collections::BTreeMap, rc::Rc};

use object::{Object, ObjectKind, ObjectSection, ObjectSymbol};

pub type Addr2LineCtx = addr2line::Context<gimli::EndianRcSlice<gimli::RunTimeEndian>>;

#[derive(Clone, Default)]
pub struct DebugInfo {
    /// Symbol table representing a mapping from an address to the name and size of a symbol.
    ///
    /// Note: address in the symbol table are already adjusted by the relocation offset.
    pub symbols: std::rc::Rc<SymbolTable>,

    /// In order to identify the locations of dynamically loaded libraries, there are several
    /// mechanisms the dynamic linker the uses to expose the `_r_debug` structure.
    pub r_debug_addr: Option<u64>,

    /// The address of the `_dl_debug_addr` symbol which contains a pointer to the `_r_debug`
    /// structure
    pub dl_debug_addr: Option<u64>,

    /// The name of the dynamic linker.
    pub dynamic_linker: Vec<u8>,

    /// Sysroot source path rewriting rules.
    pub sysroot_rewrites: Vec<(String, String)>,

    /// The program entrypoint
    pub entry_ptr: u64,

    /// Context object for symbolizing addresses.
    // @fixme: this should read data directly from the MMU instead of maintaining a copy of the
    // loaded file
    ctx: BTreeMap<u64, std::rc::Rc<Addr2LineCtx>>,

    /// The offset the original binary was relocated by.
    relocation_offset: u64,
}

impl DebugInfo {
    /// Load symbols and debug information about the loaded library.
    // @todo: consider doing this on-demand.
    // @todo: avoid needing to mantain a separate copy of the binary in memory.
    pub fn add_file(&mut self, data: &[u8], load_address: u64) -> Result<(), String> {
        let object =
            object::read::File::parse(data).map_err(|e| format!("Error parsing elf: {}", e))?;

        let relocation_offset = if object.kind() == ObjectKind::Dynamic { load_address } else { 0 };

        let endian = if object.is_little_endian() {
            gimli::RunTimeEndian::Little
        }
        else {
            gimli::RunTimeEndian::Big
        };

        let dwarf = dwarf_ctx(&object, endian)
            .map_err(|err| format!("error loading debug info from object file: {err}"))?;
        match addr2line::Context::from_dwarf(dwarf) {
            Ok(ctx) => {
                self.ctx.insert(relocation_offset, std::rc::Rc::new(ctx));
            }
            Err(e) => tracing::warn!("failed to get DWARF debug context: {e}"),
        }

        tracing::info!("Loaded object file with architecture {:?}", object.architecture());
        let is_arm = matches!(object.architecture(), object::Architecture::Arm);

        for sym in object.symbols().chain(object.dynamic_symbols()) {
            let name = match sym.name() {
                Ok(name) => name,
                Err(_) => continue,
            };
            let mut addr = sym.address() + relocation_offset;
            if addr < load_address {
                continue;
            }
            if is_arm && matches!(sym.kind(), object::SymbolKind::Text | object::SymbolKind::Label)
            {
                // Clear thumb bit
                addr &= !1;
            }

            std::rc::Rc::make_mut(&mut self.symbols).insert(
                name.to_string(),
                addr,
                sym.size(),
                get_symbol_kind(&sym),
            );
        }

        if self.dl_debug_addr.is_none() && self.r_debug_addr.is_none() {
            if let Some(addr) = self.symbols.resolve_sym("_dl_debug_addr") {
                tracing::debug!("_dl_debug_addr = {:#0x}", addr);
                self.dl_debug_addr = Some(addr);
            }

            if let Some(addr) = self.symbols.resolve_sym("_r_debug") {
                tracing::debug!("_r_debug = {:#0x}", addr);
                self.r_debug_addr = Some(addr);
            }
        }

        Ok(())
    }

    pub fn symbolize_addr(&self, addr: u64) -> Option<SourceLocation> {
        let library_base = self
            .ctx
            .range(..addr)
            .last()
            .map_or(self.relocation_offset, |(library_base, _)| *library_base);

        // Try to resolve the address using debug info
        if let Some(info) = self.addr_to_line(addr, library_base) {
            return Some(info);
        }

        // Otherwise fallback to trying to find the closest symbol
        self.get_symbol(addr)
    }

    fn get_symbol(&self, addr: u64) -> Option<SourceLocation> {
        let (name, base, _) = self.symbols.resolve_addr(addr)?;
        Some(SourceLocation {
            symbol_with_offset: Some((name.to_owned(), addr - base)),
            ..SourceLocation::default()
        })
    }

    fn addr_to_line(&self, addr: u64, library_base: u64) -> Option<SourceLocation> {
        /// Convert a `Result<T, E>` to an `Option<T>` but trace the error code
        fn trace_err<T>(value: Result<T, addr2line::gimli::Error>) -> Option<T> {
            match value {
                Ok(inner) => Some(inner),
                Err(e) => {
                    tracing::error!("symbolization error: {}", e);
                    None
                }
            }
        }

        // @fixme: we should check that the address space of the binary overlaps with the query.
        let local_addr = addr.checked_sub(library_base)?;
        let ctx = self.ctx.get(&library_base)?;

        // @todo: revisit the way inline frames are displayed
        // @todo: add support for split DWARF.
        let mut frame_iter = trace_err(ctx.find_frames(local_addr).skip_all_loads())?;
        let last_frame = (trace_err(frame_iter.next())?)?;

        let mut output = SourceLocation::default();
        output.function = Some(match get_function_name(&last_frame) {
            Some(inner) => {
                // Attempt to resolve the starting address of the function containing the current
                // address, by inspecting additional debug info depending on whether we are in a
                // regular function frame or an inlined function.
                let function_start = (|| {
                    let unit = ctx.find_dwarf_and_unit(local_addr).skip_all_loads()?;
                    let entry = unit.entry(last_frame.dw_die_offset?).ok()?;
                    resolve_start_address(&entry)
                })()
                .unwrap_or(local_addr);
                (inner.to_string(), function_start)
            }
            None => {
                let unknown_symbol = ("<unknown>", 0, SymbolKind::Unknown);
                let (name, base, _) = self.symbols.resolve_addr(addr).unwrap_or(unknown_symbol);
                (name.to_string(), base)
            }
        });

        let location = trace_err(ctx.find_location(local_addr))?;
        if let Some(location) = location {
            output.file = location.file.map(|path| self.rewrite_path(path));
            output.line = location.line;
            output.column = location.column;
        }

        Some(output)
    }

    /// Return an iterator over all symbols found in the debug info.
    pub fn debug_symbols_iter(&self) {
        todo!()
    }

    /// Return an iterator over all symbols found in the section headers.
    pub fn symbols_iter(&self) -> impl Iterator<Item = (u64, u64, &str, SymbolKind)> {
        self.symbols.addr_to_sym.iter().flat_map(|(start, entries)| {
            entries.iter().map(|(name, len, kind)| (*start, *len, name.as_str(), *kind))
        })
    }

    /// Strip the original prefix (from the debug info) from `path` and return the remapped host
    /// prefix and the rest of the path.
    fn strip_prefix<'a, 'b>(&'a self, path: &'b str) -> Option<(&'a str, &'b str)> {
        for (debug_info_prefix, host_prefix) in &self.sysroot_rewrites {
            if path.starts_with(debug_info_prefix) {
                return Some((host_prefix, &path[debug_info_prefix.len()..]));
            }
        }
        None
    }

    /// Convert a path from the debug info to a path on disk.
    fn rewrite_path(&self, path: &str) -> String {
        match self.strip_prefix(path) {
            Some((prefix, suffix)) => format!("{prefix}{suffix}"),
            None => path.to_string(),
        }
    }
}

fn dwarf_ctx(
    object: &object::File,
    endian: gimli::RunTimeEndian,
) -> anyhow::Result<gimli::Dwarf<gimli::EndianRcSlice<gimli::RunTimeEndian>>> {
    let load_section = |id: gimli::SectionId| -> anyhow::Result<Rc<[u8]>> {
        Ok(match object.section_by_name(id.name()) {
            Some(section) => section.uncompressed_data()?.into(),
            None => Rc::new([]),
        })
    };
    let dwarf_sections = gimli::DwarfSections::load(load_section)?;

    let borrow_section = |section: &Rc<[u8]>| gimli::EndianRcSlice::new(section.clone(), endian);
    let dwarf = dwarf_sections.borrow(borrow_section);

    Ok(dwarf)
}

fn resolve_start_address<R, Offset>(
    entry: &addr2line::gimli::DebuggingInformationEntry<R, Offset>,
) -> Option<u64>
where
    R: addr2line::gimli::Reader<Offset = Offset>,
    Offset: addr2line::gimli::ReaderOffset,
{
    match entry.tag() {
        addr2line::gimli::constants::DW_TAG_subprogram => {
            if let Some(addr2line::gimli::AttributeValue::Addr(addr)) =
                entry.attr_value(addr2line::gimli::constants::DW_AT_low_pc).ok().flatten()
            {
                return Some(addr);
            }
        }
        addr2line::gimli::constants::DW_TAG_inlined_subroutine => {
            if let Some(addr2line::gimli::AttributeValue::Addr(addr)) =
                entry.attr_value(addr2line::gimli::constants::DW_AT_entry_pc).ok().flatten()
            {
                return Some(addr);
            }
        }
        _ => {}
    }
    None
}

fn get_function_name<'a, T: 'a>(
    frame: &'a addr2line::Frame<'a, T>,
) -> Option<std::borrow::Cow<'a, str>>
where
    T: addr2line::gimli::Reader,
{
    let function = frame.function.as_ref()?;
    let demangled = function.demangle().ok()?;
    Some(demangled)
}

#[derive(Debug, Clone, Default)]
pub struct SymbolTable {
    pub sym_to_addr: BTreeMap<String, (u64, u64, SymbolKind)>,
    pub addr_to_sym: BTreeMap<u64, Vec<(String, u64, SymbolKind)>>,
}

#[derive(Debug, Copy, Clone)]
pub enum SymbolKind {
    Function,
    Label,
    Unknown,
    Null,
    Object,
    File,
}

fn get_symbol_kind(sym: &object::Symbol) -> SymbolKind {
    match sym.kind() {
        object::SymbolKind::Text => SymbolKind::Function,
        object::SymbolKind::Label => SymbolKind::Label,
        object::SymbolKind::Data => SymbolKind::Object,
        object::SymbolKind::Section => SymbolKind::Unknown,
        object::SymbolKind::File => SymbolKind::File,
        object::SymbolKind::Tls => SymbolKind::Unknown,
        _ => SymbolKind::Unknown,
    }
}

impl SymbolTable {
    /// Inserts a value into the symbol table
    pub fn insert(&mut self, name: String, addr: u64, len: u64, kind: SymbolKind) {
        self.sym_to_addr.insert(name.clone(), (addr, len, kind));
        self.addr_to_sym.entry(addr).or_default().push((name, len, kind));
    }

    /// Attempts to resolve a address to a symbol returning the name of the symbol and its starting
    /// address
    pub fn resolve_addr(&self, addr: u64) -> Option<(&str, u64, SymbolKind)> {
        // @fixme: optimize this search to avoid needing to iterate though the entire symbol array
        for (start, entries) in self.addr_to_sym.range(..=addr).rev() {
            let mut filtered_iter = entries.iter().filter(|(_, len, _)| addr < start + len);

            // First try to find a function-like symbol that matches the current address.
            if let Some((name, _, kind)) =
                filtered_iter.clone().find(|(_, _, kind)| matches!(kind, SymbolKind::Function))
            {
                return Some((name, *start, *kind));
            }

            // Otherwise just get an arbitary entry.
            if let Some((name, _, kind)) = filtered_iter.next() {
                return Some((name, *start, *kind));
            }
        }

        // If we still failed to find a maching symbol, just get the symbol that is closest.
        for (start, entries) in self.addr_to_sym.range(..=addr).rev() {
            if let Some((name, _, kind)) =
                entries.iter().find(|(_, _, kind)| matches!(kind, SymbolKind::Function))
            {
                return Some((name, *start, *kind));
            }
        }

        None
    }

    /// Attempts to resolve a symbol to an address
    pub fn resolve_sym(&self, symbol: &str) -> Option<u64> {
        self.sym_to_addr.get(symbol).map(|x| x.0)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SourceLocation {
    pub symbol_with_offset: Option<(String, u64)>,
    pub function: Option<(String, u64)>,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub column: Option<u32>,
    pub library_name_and_offset: Option<(Vec<u8>, u64)>,
}

impl SourceLocation {
    pub fn label(&self) -> Option<String> {
        self.function.as_ref().map(|(name, _)| name.clone()).or_else(|| {
            self.symbol_with_offset.as_ref().map(|(name, offset)| match offset {
                0 => name.clone(),
                _ => format!("{name}+{offset:#x}"),
            })
        })
    }
}

impl SourceLocation {
    pub fn display_file(&self) -> SourceLocationDisplayFile {
        SourceLocationDisplayFile { source: self }
    }
}

impl std::fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.function.as_ref(), self.symbol_with_offset.as_ref()) {
            (Some((function, _)), _) => write!(f, "{}", function)?,
            (_, Some((symbol, 0))) => write!(f, "{}", symbol)?,
            (_, Some((symbol, offset))) => write!(f, "{}+{:#0x}", symbol, offset)?,
            _ => {
                if let Some((lib, lib_offset)) = self.library_name_and_offset.as_ref() {
                    return write!(
                        f,
                        "<unknown> ({lib_offset:#012x} {})",
                        String::from_utf8_lossy(lib)
                    );
                }

                write!(f, "<unknown>")?
            }
        }

        if let Some(file) = self.file.as_ref() {
            write!(f, " at {}", file)?;
            if let Some(line) = self.line {
                write!(f, ":{}", line)?;
            }
            if let Some(column) = self.column {
                write!(f, ":{}", column)?;
            }
        }

        Ok(())
    }
}

pub struct SourceLocationDisplayFile<'a> {
    source: &'a SourceLocation,
}

impl<'a> std::fmt::Display for SourceLocationDisplayFile<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(file) = self.source.file.as_ref() {
            write!(f, "{}", file)?;
            if let Some(line) = self.source.line {
                write!(f, ":{}", line)?;
            }
            if let Some(column) = self.source.column {
                write!(f, ":{}", column)?;
            }
        }

        Ok(())
    }
}
