

pub enum Armv7t {}

impl gdbstub::arch::Arch for Armv7t {
    type Usize = u32;
    type Registers = gdbstub_arch::arm::reg::ArmCoreRegs;
    type RegId = gdbstub_arch::arm::reg::id::ArmCoreRegId;
    type BreakpointKind = gdbstub_arch::arm::ArmBreakpointKind;

    fn target_description_xml() -> Option<&'static str> {
        Some(r#"<target version="1.0"><architecture>armv4</architecture></target>"#)
    }
}