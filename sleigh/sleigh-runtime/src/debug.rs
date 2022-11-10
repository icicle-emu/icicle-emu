use crate::decoder::{DecodedConstructor, SubtableCtx};

impl std::fmt::Debug for SubtableCtx<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let constructor_id = self.constructor.id;
        let constructor = self.constructor_info();
        let constructor_line = self
            .data
            .debug_info
            .constructors
            .get(constructor_id as usize)
            .map_or("unknown", |x| x.line.as_str());

        f.debug_struct("Subtable")
            .field("id", &constructor.table)
            .field("constructor", &constructor_id)
            .field("constructor_line", &constructor_line)
            .field("locals", &LocalsDebug { ctx: self, locals: self.locals() })
            .field("subtables", &SubtableListDebug { ctx: self, list: self.subtables() })
            .finish()
    }
}

struct SubtableListDebug<'a, 'b> {
    ctx: &'a SubtableCtx<'b, 'b>,
    list: &'a [DecodedConstructor],
}

impl std::fmt::Debug for SubtableListDebug<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.list.iter().map(|subtable| self.ctx.visit_constructor(*subtable)))
            .finish()
    }
}

struct LocalsDebug<'a, 'b> {
    #[allow(unused)]
    ctx: &'a SubtableCtx<'b, 'b>,
    locals: &'a [i64],
}

impl std::fmt::Debug for LocalsDebug<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.locals.iter()).finish()
    }
}
