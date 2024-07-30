use std::{collections::HashSet, rc::Rc};

use icicle_vm::{
    cpu::{
        mem::{self, MemError, MemResult},
        utils::XorShiftRng,
        Environment,
    },
    msp430::Msp430,
};

use crate::{FuzzConfig, Runnable};

#[derive(Clone)]
pub struct RandomIoTarget {
    fuzz_addrs: Option<Rc<HashSet<u64>>>,
    fixed_seed: Option<u64>,
}

impl RandomIoTarget {
    pub fn new() -> Self {
        Self { fuzz_addrs: None, fixed_seed: None }
    }
}

impl crate::FuzzTarget for RandomIoTarget {
    fn create_vm(&mut self, config: &mut FuzzConfig) -> anyhow::Result<icicle_vm::Vm> {
        anyhow::ensure!(!config.guest_args.is_empty(), "program not specified in input arguments");

        if let Some(fuzz_addrs) = config.msp430.fuzz_addrs.as_ref() {
            self.fuzz_addrs = Some(Rc::new(fuzz_addrs.clone()));
        }
        self.fixed_seed = config.msp430.fixed_seed;

        let mut cpu_config = config.cpu_config();
        // Currently we allow interrupts to be trigged in the middle of blocks, this prevents us
        // from enabling block level optimizations.
        cpu_config.optimize_block = false;
        let mut vm = icicle_vm::build(&cpu_config)?;

        let mut msp430_config = icicle_vm::msp430::Config {
            load_addr: config.msp430.load_addr.unwrap_or(0),
            interrupt_interval: config.msp430.interrupt_interval,
            ..icicle_vm::msp430::Config::default()
        };
        if let Some(mcu) = config.msp430.mcu.as_ref() {
            msp430_config.mcu = mcu.clone();
        }

        let mut env = Msp430::new(&vm.cpu, msp430_config)?;
        env.load(&mut vm.cpu, config.guest_args[0].as_bytes())
            .map_err(|e| anyhow::format_err!("{}", e))?;

        if let Some(exit_addr) = env.debug_info.symbols.resolve_sym("exit") {
            tracing::info!("Configuring exit at: {exit_addr:#0x}");
            vm.lifter.patchers.push(Box::new(move |block: &mut pcode::Block| {
                if block.instructions.iter().any(|x| {
                    matches!(x.op, pcode::Op::InstructionMarker)
                        && x.inputs.first().const_eq(exit_addr)
                }) {
                    block.instructions.truncate(1);
                    block.push((pcode::Op::Exception, (crate::ExceptionCode::Halt as u32, 0_u64)));
                }
            }));
        }

        vm.set_env(env);
        Ok(vm)
    }

    fn initialize_vm(&mut self, config: &FuzzConfig, vm: &mut icicle_vm::Vm) -> anyhow::Result<()> {
        if let Some(var) = vm.cpu.arch.sleigh.get_reg("afl.prev_pc").map(|x| x.var) {
            let env = vm.env_mut::<Msp430>().unwrap();
            env.afl_prev_pc = Some(var);
        }

        if let Some(addr) = config.start_addr {
            vm.run_until(addr);
        }

        Ok(())
    }
}

impl Runnable for RandomIoTarget {
    fn set_input(&mut self, vm: &mut icicle_vm::Vm, input: &[u8]) -> anyhow::Result<()> {
        let env = vm.env_mut::<Msp430>().unwrap();

        let (input, rand_seed) = match self.fixed_seed {
            Some(seed) => {
                env.interrupt_rng.seed = seed;
                (input, seed >> 4)
            }

            // The first byte of the input is used to seed various RNGs, note we intentionally
            // restrict the range of the seed to avoid too many excess paths.
            None => {
                let rand_seed = input.first().copied().unwrap_or(0xaa);
                env.interrupt_rng.seed = (rand_seed & 0xf) as u64;
                env.interrupt_rng.next();
                (input.get(1..).unwrap_or(&[]), (rand_seed >> 4) as u64)
            }
        };

        let mut handler = env.unknown_peripheral_handler.inner.borrow_mut();
        match handler.as_mut_any().downcast_mut::<InputHandler>() {
            Some(handler) => handler.reset(input, rand_seed),
            None => {
                *handler =
                    Box::new(InputHandler::new(self.fuzz_addrs.clone(), input.to_vec(), rand_seed));
            }
        };

        Ok(())
    }

    fn modify_input(
        &mut self,
        vm: &mut icicle_vm::Vm,
        offset: u64,
        input: &[u8],
    ) -> anyhow::Result<()> {
        let env = vm.env_ref::<Msp430>().unwrap();

        let mut handler_ref = env.unknown_peripheral_handler.inner.borrow_mut();
        let handler = handler_ref
            .as_mut_any()
            .downcast_mut::<InputHandler>()
            .ok_or_else(|| anyhow::format_err!("Input not configured"))?;

        handler.offset = offset as usize;
        handler.data.clear();
        handler.data.extend_from_slice(input);

        Ok(())
    }
}

struct InputHandler {
    /// The set of peripheral addresses mapped to `data` instead of just handled randomly.
    fuzz_addrs: Option<Rc<HashSet<u64>>>,

    /// The input bytes provided by the fuzzer.
    data: Vec<u8>,

    /// The offset within `data` to read the next peripheral read from.
    offset: usize,

    /// Random number generator used for
    rng: XorShiftRng,
}

impl InputHandler {
    #[allow(unused)]
    fn new(fuzz_addrs: Option<Rc<HashSet<u64>>>, data: Vec<u8>, seed: u64) -> Self {
        Self { fuzz_addrs, data, offset: 0, rng: XorShiftRng::new(seed) }
    }

    pub fn reset(&mut self, data: &[u8], seed: u64) {
        self.data.clear();
        self.data.extend_from_slice(data);
        self.offset = 0;
        self.rng = XorShiftRng::new(seed);
    }
}

impl mem::IoMemory for InputHandler {
    fn read(&mut self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
        if let Some(entries) = self.fuzz_addrs.as_ref() {
            if !entries.contains(&addr) {
                self.rng.fill_bytes(buf);
                return Ok(());
            }
        }

        if self.data.len() < self.offset + buf.len() {
            return Err(MemError::ReadWatch);
        }

        buf.copy_from_slice(&self.data[self.offset..][..buf.len()]);
        self.offset += buf.len();

        Ok(())
    }

    fn write(&mut self, _addr: u64, _value: &[u8]) -> MemResult<()> {
        Ok(())
    }

    fn snapshot(&mut self) -> Box<dyn std::any::Any> {
        Box::new((self.offset, self.rng))
    }

    fn restore(&mut self, snapshot: &Box<dyn std::any::Any>) {
        // Note: the input handler may have been replaced since the snapshot was created, which
        // prevents us from restoring the state here.
        //
        // @fixme: this can cause divergance issues.
        if let Some((offset, rng)) = snapshot.downcast_ref::<(usize, XorShiftRng)>() {
            self.offset = *offset;
            self.rng = *rng;
        }
    }
}

const BLOCK_SIZE: usize = 16;

struct Block {
    data: [u8; BLOCK_SIZE],
    offset: u8,
}

impl Block {
    fn read(&mut self, buf: &mut [u8]) -> bool {
        if buf.len() > self.data.len() - self.offset as usize {
            return false;
        }
        buf.copy_from_slice(&self.data[self.offset as usize..][..buf.len()]);
        self.offset += buf.len() as u8;
        true
    }
}

struct BlockInputHandler<I: AsRef<[u8]> + 'static> {
    blocks: std::collections::HashMap<u64, Block>,
    offset: usize,
    data: I,
}

impl<I: AsRef<[u8]> + 'static> BlockInputHandler<I> {
    #[allow(unused)]
    fn new(data: I) -> Self {
        Self { offset: 0, data, blocks: std::collections::HashMap::new() }
    }
}

impl<I: AsRef<[u8]> + 'static> mem::IoMemory for BlockInputHandler<I> {
    fn read(&mut self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
        let data = self.data.as_ref();

        if self.blocks.get_mut(&addr).map_or(false, |x| x.read(buf)) {
            return Ok(());
        }

        if data.len() - self.offset < BLOCK_SIZE || buf.len() >= BLOCK_SIZE {
            return Err(MemError::ReadWatch);
        }

        let mut block = Block { data: [0; BLOCK_SIZE], offset: 0 };
        block.data.copy_from_slice(&data[self.offset..][..BLOCK_SIZE]);
        self.offset += BLOCK_SIZE;

        block.read(buf);
        self.blocks.insert(addr, block);
        Ok(())
    }

    fn write(&mut self, _addr: u64, _value: &[u8]) -> MemResult<()> {
        Ok(())
    }
}
