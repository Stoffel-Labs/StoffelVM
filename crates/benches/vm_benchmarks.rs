use criterion::Throughput;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;
use stoffel_vm::core_types::{ClearShareInput, ClearShareValue, ShareData, ShareType, Value};
use stoffel_vm::core_vm::VirtualMachine;
use stoffel_vm::functions::VMFunction;
use stoffel_vm::instructions::Instruction;
use stoffel_vm::net::mpc_engine::{
    AsyncMpcEngine, MpcCapabilities, MpcEngine, MpcEngineResult, MpcSessionTopology,
};
use stoffel_vm::runtime_hooks::HookEvent;
use stoffel_vm_types::activations::ActivationRecord;
use stoffel_vm_types::registers::{RegisterFile, RegisterIndex, RegisterLayout};

const INSTRUCTION_COUNTS: [usize; 3] = [100, 1_000, 10_000];
const CALL_COUNTS: [usize; 3] = [100, 1_000, 5_000];
const TABLE_OPERATION_COUNTS: [usize; 3] = [10, 100, 1_000];
const REGISTER_BANK_COUNTS: [usize; 3] = [10, 100, 1_000];
const ASYNC_ENTRY_COUNTS: [usize; 3] = [1, 4, 16];
const LONG_DIAGNOSTIC_COUNT: usize = 10_000_000;
const STRAIGHT_LINE_COUNT: usize = 10_000_000;
const STACK_DIAGNOSTIC_COUNT: usize = 100_000;
const FRAME_DIAGNOSTIC_COUNT: usize = 100_000;

struct ImmediateAsyncEngine;

impl ImmediateAsyncEngine {
    fn share_data_for_clear(clear: &ClearShareInput) -> ShareData {
        let byte = match clear.value() {
            ClearShareValue::Integer(value) => value.to_le_bytes()[0],
            ClearShareValue::FixedPoint(value) => (value.0 as i64).to_le_bytes()[0],
            ClearShareValue::Boolean(value) => u8::from(value),
        };
        ShareData::Opaque(vec![byte])
    }

    fn open_share_bytes(share_bytes: &[u8]) -> ClearShareValue {
        ClearShareValue::Integer(share_bytes.first().copied().unwrap_or_default() as i64)
    }
}

impl MpcEngine for ImmediateAsyncEngine {
    fn protocol_name(&self) -> &'static str {
        "bench-immediate-async"
    }

    fn topology(&self) -> MpcSessionTopology {
        MpcSessionTopology::try_new(1, 0, 1, 0).expect("benchmark topology should be valid")
    }

    fn is_ready(&self) -> bool {
        true
    }

    fn start(&self) -> MpcEngineResult<()> {
        Ok(())
    }

    fn input_share(&self, clear: ClearShareInput) -> MpcEngineResult<ShareData> {
        Ok(Self::share_data_for_clear(&clear))
    }

    fn open_share(&self, _ty: ShareType, share_bytes: &[u8]) -> MpcEngineResult<ClearShareValue> {
        Ok(Self::open_share_bytes(share_bytes))
    }

    fn capabilities(&self) -> MpcCapabilities {
        MpcCapabilities::empty()
    }
}

#[async_trait::async_trait]
impl AsyncMpcEngine for ImmediateAsyncEngine {
    async fn input_share_async(&self, clear: ClearShareInput) -> MpcEngineResult<ShareData> {
        Ok(Self::share_data_for_clear(&clear))
    }

    async fn open_share_async(
        &self,
        _ty: ShareType,
        share_bytes: &[u8],
    ) -> MpcEngineResult<ClearShareValue> {
        Ok(Self::open_share_bytes(share_bytes))
    }
}

fn function(
    name: &str,
    register_count: usize,
    instructions: Vec<Instruction>,
    labels: HashMap<String, usize>,
) -> VMFunction {
    VMFunction::new(
        name.to_owned(),
        vec![],
        vec![],
        None,
        register_count,
        instructions,
        labels,
    )
}

fn vm_with(functions: impl IntoIterator<Item = VMFunction>) -> VirtualMachine {
    let mut vm = VirtualMachine::new();
    for function in functions {
        vm.register_function(function);
    }
    vm
}

fn vm_with_register_layout(
    functions: impl IntoIterator<Item = VMFunction>,
    layout: RegisterLayout,
    engine: Arc<dyn MpcEngine>,
) -> VirtualMachine {
    let mut vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_builtins(false)
        .with_register_layout(layout)
        .with_mpc_engine(engine)
        .build();
    for function in functions {
        vm.register_function(function);
    }
    vm
}

fn warm(mut vm: VirtualMachine, entry: &str) -> VirtualMachine {
    vm.execute(entry).unwrap();
    vm
}

fn add_chain(operation_count: usize) -> VMFunction {
    let mut instructions = Vec::with_capacity(operation_count + 3);
    instructions.push(Instruction::LDI(0, Value::I64(0)));
    instructions.push(Instruction::LDI(1, Value::I64(1)));
    instructions.extend((0..operation_count).map(|_| Instruction::ADD(0, 0, 1)));
    instructions.push(Instruction::RET(0));

    function("add_chain", 2, instructions, HashMap::new())
}

fn mov_chain(operation_count: usize) -> VMFunction {
    let mut instructions = Vec::with_capacity(operation_count + 2);
    instructions.push(Instruction::LDI(0, Value::I64(1)));
    instructions.extend((0..operation_count).map(|i| {
        if i % 2 == 0 {
            Instruction::MOV(1, 0)
        } else {
            Instruction::MOV(0, 1)
        }
    }));
    instructions.push(Instruction::RET(0));

    function("mov_chain", 2, instructions, HashMap::new())
}

fn branch_loop(iterations: usize) -> VMFunction {
    let mut labels = HashMap::new();
    labels.insert("loop".to_owned(), 3);

    function(
        "branch_loop",
        3,
        vec![
            Instruction::LDI(0, Value::I64(0)),
            Instruction::LDI(1, Value::I64(1)),
            Instruction::LDI(2, Value::I64(iterations as i64)),
            Instruction::ADD(0, 0, 1),
            Instruction::CMP(0, 2),
            Instruction::JMPLT("loop".to_owned()),
            Instruction::RET(0),
        ],
        labels,
    )
}

fn nop_loop(iterations: usize) -> VMFunction {
    let mut labels = HashMap::new();
    labels.insert("loop".to_owned(), 3);

    function(
        "nop_loop",
        3,
        vec![
            Instruction::LDI(0, Value::I64(0)),
            Instruction::LDI(1, Value::I64(1)),
            Instruction::LDI(2, Value::I64(iterations as i64)),
            Instruction::NOP,
            Instruction::ADD(0, 0, 1),
            Instruction::CMP(0, 2),
            Instruction::JMPLT("loop".to_owned()),
            Instruction::RET(0),
        ],
        labels,
    )
}

fn cmp_read_loop(iterations: usize) -> VMFunction {
    let mut labels = HashMap::new();
    labels.insert("loop".to_owned(), 5);

    function(
        "cmp_read_loop",
        5,
        vec![
            Instruction::LDI(0, Value::I64(0)),
            Instruction::LDI(1, Value::I64(1)),
            Instruction::LDI(2, Value::I64(iterations as i64)),
            Instruction::LDI(3, Value::I64(7)),
            Instruction::LDI(4, Value::I64(11)),
            Instruction::CMP(3, 4),
            Instruction::ADD(0, 0, 1),
            Instruction::CMP(0, 2),
            Instruction::JMPLT("loop".to_owned()),
            Instruction::RET(0),
        ],
        labels,
    )
}

fn branch_always_taken_loop(iterations: usize) -> VMFunction {
    let mut labels = HashMap::new();
    labels.insert("loop".to_owned(), 5);
    labels.insert("taken".to_owned(), 8);

    function(
        "branch_always_taken_loop",
        5,
        vec![
            Instruction::LDI(0, Value::I64(0)),
            Instruction::LDI(1, Value::I64(1)),
            Instruction::LDI(2, Value::I64(iterations as i64)),
            Instruction::LDI(3, Value::I64(7)),
            Instruction::LDI(4, Value::I64(7)),
            Instruction::CMP(3, 4),
            Instruction::JMPEQ("taken".to_owned()),
            Instruction::RET(0),
            Instruction::ADD(0, 0, 1),
            Instruction::CMP(0, 2),
            Instruction::JMPLT("loop".to_owned()),
            Instruction::RET(0),
        ],
        labels,
    )
}

fn branch_never_taken_loop(iterations: usize) -> VMFunction {
    let mut labels = HashMap::new();
    labels.insert("loop".to_owned(), 5);
    labels.insert("taken".to_owned(), 11);

    function(
        "branch_never_taken_loop",
        5,
        vec![
            Instruction::LDI(0, Value::I64(0)),
            Instruction::LDI(1, Value::I64(1)),
            Instruction::LDI(2, Value::I64(iterations as i64)),
            Instruction::LDI(3, Value::I64(7)),
            Instruction::LDI(4, Value::I64(11)),
            Instruction::CMP(3, 4),
            Instruction::JMPEQ("taken".to_owned()),
            Instruction::ADD(0, 0, 1),
            Instruction::CMP(0, 2),
            Instruction::JMPLT("loop".to_owned()),
            Instruction::RET(0),
            Instruction::RET(0),
        ],
        labels,
    )
}

fn branch_alternating_loop(iterations: usize) -> VMFunction {
    let mut labels = HashMap::new();
    labels.insert("loop".to_owned(), 5);
    labels.insert("taken".to_owned(), 10);
    labels.insert("join".to_owned(), 11);

    function(
        "branch_alternating_loop",
        5,
        vec![
            Instruction::LDI(0, Value::I64(0)),
            Instruction::LDI(1, Value::I64(1)),
            Instruction::LDI(2, Value::I64(iterations as i64)),
            Instruction::LDI(3, Value::I64(0)),
            Instruction::LDI(4, Value::I64(0)),
            Instruction::CMP(3, 4),
            Instruction::JMPEQ("taken".to_owned()),
            Instruction::LDI(3, Value::I64(0)),
            Instruction::JMP("join".to_owned()),
            Instruction::RET(0),
            Instruction::LDI(3, Value::I64(1)),
            Instruction::ADD(0, 0, 1),
            Instruction::CMP(0, 2),
            Instruction::JMPLT("loop".to_owned()),
            Instruction::RET(0),
        ],
        labels,
    )
}

fn straight_nop(operation_count: usize) -> VMFunction {
    let mut instructions = Vec::with_capacity(operation_count + 1);
    instructions.extend(std::iter::repeat_n(Instruction::NOP, operation_count));
    instructions.push(Instruction::RET(0));

    function("straight_nop", 1, instructions, HashMap::new())
}

fn straight_mov(operation_count: usize) -> VMFunction {
    let mut instructions = Vec::with_capacity(operation_count + 2);
    instructions.push(Instruction::LDI(0, Value::I64(1)));
    instructions.extend(std::iter::repeat_n(Instruction::MOV(0, 0), operation_count));
    instructions.push(Instruction::RET(0));

    function("straight_mov", 1, instructions, HashMap::new())
}

fn straight_add(operation_count: usize) -> VMFunction {
    let mut instructions = Vec::with_capacity(operation_count + 3);
    instructions.push(Instruction::LDI(0, Value::I64(0)));
    instructions.push(Instruction::LDI(1, Value::I64(1)));
    instructions.extend(std::iter::repeat_n(
        Instruction::ADD(0, 0, 1),
        operation_count,
    ));
    instructions.push(Instruction::RET(0));

    function("straight_add", 2, instructions, HashMap::new())
}

fn straight_binary_instruction(
    name: &str,
    operation_count: usize,
    lhs: Value,
    rhs: Value,
    instruction: fn(usize, usize, usize) -> Instruction,
) -> VMFunction {
    let mut instructions = Vec::with_capacity(operation_count + 4);
    instructions.push(Instruction::LDI(1, lhs));
    instructions.push(Instruction::LDI(2, rhs));
    instructions.extend(std::iter::repeat_n(instruction(0, 1, 2), operation_count));
    instructions.push(Instruction::RET(0));

    function(name, 3, instructions, HashMap::new())
}

fn straight_unary_instruction(
    name: &str,
    operation_count: usize,
    src: Value,
    instruction: fn(usize, usize) -> Instruction,
) -> VMFunction {
    let mut instructions = Vec::with_capacity(operation_count + 3);
    instructions.push(Instruction::LDI(1, src));
    instructions.extend(std::iter::repeat_n(instruction(0, 1), operation_count));
    instructions.push(Instruction::RET(0));

    function(name, 2, instructions, HashMap::new())
}

fn straight_sub(operation_count: usize) -> VMFunction {
    straight_binary_instruction(
        "straight_sub",
        operation_count,
        Value::I64(9),
        Value::I64(4),
        Instruction::SUB,
    )
}

fn straight_mul(operation_count: usize) -> VMFunction {
    straight_binary_instruction(
        "straight_mul",
        operation_count,
        Value::I64(6),
        Value::I64(7),
        Instruction::MUL,
    )
}

fn straight_div(operation_count: usize) -> VMFunction {
    straight_binary_instruction(
        "straight_div",
        operation_count,
        Value::I64(42),
        Value::I64(3),
        Instruction::DIV,
    )
}

fn straight_mod(operation_count: usize) -> VMFunction {
    straight_binary_instruction(
        "straight_mod",
        operation_count,
        Value::I64(43),
        Value::I64(5),
        Instruction::MOD,
    )
}

fn straight_and(operation_count: usize) -> VMFunction {
    straight_binary_instruction(
        "straight_and",
        operation_count,
        Value::I64(0b1010),
        Value::I64(0b1100),
        Instruction::AND,
    )
}

fn straight_or(operation_count: usize) -> VMFunction {
    straight_binary_instruction(
        "straight_or",
        operation_count,
        Value::I64(0b1010),
        Value::I64(0b0101),
        Instruction::OR,
    )
}

fn straight_xor(operation_count: usize) -> VMFunction {
    straight_binary_instruction(
        "straight_xor",
        operation_count,
        Value::I64(0b1010),
        Value::I64(0b1100),
        Instruction::XOR,
    )
}

fn straight_not(operation_count: usize) -> VMFunction {
    straight_unary_instruction(
        "straight_not",
        operation_count,
        Value::I64(0b1010),
        Instruction::NOT,
    )
}

fn straight_shl(operation_count: usize) -> VMFunction {
    straight_binary_instruction(
        "straight_shl",
        operation_count,
        Value::I64(1),
        Value::I64(3),
        Instruction::SHL,
    )
}

fn straight_shr(operation_count: usize) -> VMFunction {
    straight_binary_instruction(
        "straight_shr",
        operation_count,
        Value::I64(64),
        Value::I64(2),
        Instruction::SHR,
    )
}

fn straight_load_stack(operation_count: usize) -> VMFunction {
    let mut instructions = Vec::with_capacity(operation_count + 3);
    instructions.push(Instruction::LDI(0, Value::I64(7)));
    instructions.push(Instruction::PUSHARG(0));
    instructions.extend(std::iter::repeat_n(Instruction::LD(1, 0), operation_count));
    instructions.push(Instruction::RET(1));

    function("straight_load_stack", 2, instructions, HashMap::new())
}

fn straight_pusharg(operation_count: usize) -> VMFunction {
    let mut instructions = Vec::with_capacity(operation_count + 2);
    instructions.push(Instruction::LDI(0, Value::I64(7)));
    instructions.extend(std::iter::repeat_n(
        Instruction::PUSHARG(0),
        operation_count,
    ));
    instructions.push(Instruction::RET(0));

    function("straight_pusharg", 1, instructions, HashMap::new())
}

fn straight_write_const(operation_count: usize) -> VMFunction {
    let mut instructions = Vec::with_capacity(operation_count + 1);
    instructions.extend(std::iter::repeat_n(
        Instruction::LDI(0, Value::I64(1)),
        operation_count,
    ));
    instructions.push(Instruction::RET(0));

    function("straight_write_const", 1, instructions, HashMap::new())
}

fn straight_cmp_read_only_proxy(operation_count: usize) -> VMFunction {
    let mut instructions = Vec::with_capacity(operation_count + 3);
    instructions.push(Instruction::LDI(0, Value::I64(7)));
    instructions.push(Instruction::LDI(1, Value::I64(7)));
    instructions.extend(std::iter::repeat_n(Instruction::CMP(0, 1), operation_count));
    instructions.push(Instruction::RET(0));

    function(
        "straight_cmp_read_only_proxy",
        2,
        instructions,
        HashMap::new(),
    )
}

fn straight_mov_distinct(operation_count: usize) -> VMFunction {
    let mut instructions = Vec::with_capacity(operation_count + 3);
    instructions.push(Instruction::LDI(0, Value::I64(0)));
    instructions.push(Instruction::LDI(1, Value::I64(1)));
    instructions.extend(std::iter::repeat_n(Instruction::MOV(0, 1), operation_count));
    instructions.push(Instruction::RET(0));

    function("straight_mov_distinct", 2, instructions, HashMap::new())
}

fn straight_mov_self_alias(operation_count: usize) -> VMFunction {
    let mut instructions = Vec::with_capacity(operation_count + 2);
    instructions.push(Instruction::LDI(0, Value::I64(1)));
    instructions.extend(std::iter::repeat_n(Instruction::MOV(0, 0), operation_count));
    instructions.push(Instruction::RET(0));

    function("straight_mov_self_alias", 1, instructions, HashMap::new())
}

fn straight_mov_reverse_adjacent(operation_count: usize) -> VMFunction {
    let mut instructions = Vec::with_capacity(operation_count + 3);
    instructions.push(Instruction::LDI(0, Value::I64(1)));
    instructions.push(Instruction::LDI(1, Value::I64(0)));
    instructions.extend(std::iter::repeat_n(Instruction::MOV(1, 0), operation_count));
    instructions.push(Instruction::RET(1));

    function(
        "straight_mov_reverse_adjacent",
        2,
        instructions,
        HashMap::new(),
    )
}

fn straight_mov_far_to_low(operation_count: usize) -> VMFunction {
    let mut instructions = Vec::with_capacity(operation_count + 2);
    instructions.push(Instruction::LDI(15, Value::I64(1)));
    instructions.extend(std::iter::repeat_n(
        Instruction::MOV(0, 15),
        operation_count,
    ));
    instructions.push(Instruction::RET(0));

    function("straight_mov_far_to_low", 16, instructions, HashMap::new())
}

fn straight_mov_low_to_far(operation_count: usize) -> VMFunction {
    let mut instructions = Vec::with_capacity(operation_count + 2);
    instructions.push(Instruction::LDI(0, Value::I64(1)));
    instructions.extend(std::iter::repeat_n(
        Instruction::MOV(15, 0),
        operation_count,
    ));
    instructions.push(Instruction::RET(15));

    function("straight_mov_low_to_far", 16, instructions, HashMap::new())
}

fn straight_mov_zero_source(operation_count: usize) -> VMFunction {
    let mut instructions = Vec::with_capacity(operation_count + 3);
    instructions.push(Instruction::LDI(0, Value::I64(1)));
    instructions.push(Instruction::LDI(1, Value::I64(0)));
    instructions.extend(std::iter::repeat_n(Instruction::MOV(0, 1), operation_count));
    instructions.push(Instruction::RET(0));

    function("straight_mov_zero_source", 2, instructions, HashMap::new())
}

fn straight_mov_unit_source(operation_count: usize) -> VMFunction {
    let mut instructions = Vec::with_capacity(operation_count + 2);
    instructions.push(Instruction::LDI(0, Value::I64(1)));
    instructions.extend(std::iter::repeat_n(Instruction::MOV(0, 1), operation_count));
    instructions.push(Instruction::RET(0));

    function("straight_mov_unit_source", 2, instructions, HashMap::new())
}

fn straight_add_distinct(operation_count: usize) -> VMFunction {
    let mut instructions = Vec::with_capacity(operation_count + 4);
    instructions.push(Instruction::LDI(0, Value::I64(0)));
    instructions.push(Instruction::LDI(1, Value::I64(1)));
    instructions.push(Instruction::LDI(2, Value::I64(2)));
    instructions.extend(std::iter::repeat_n(
        Instruction::ADD(0, 1, 2),
        operation_count,
    ));
    instructions.push(Instruction::RET(0));

    function("straight_add_distinct", 3, instructions, HashMap::new())
}

fn vm_noop_target() -> VMFunction {
    function(
        "vm_noop",
        1,
        vec![Instruction::LDI(0, Value::I64(1)), Instruction::RET(0)],
        HashMap::new(),
    )
}

fn vm_add_target() -> VMFunction {
    VMFunction::new(
        "vm_add".to_owned(),
        vec!["lhs".to_owned(), "rhs".to_owned()],
        Vec::new(),
        None,
        2,
        vec![Instruction::ADD(0, 0, 1), Instruction::RET(0)],
        HashMap::new(),
    )
}

fn call_loop(entry: &str, callee: &str, call_count: usize) -> VMFunction {
    let mut instructions = Vec::with_capacity(call_count + 1);
    instructions.extend((0..call_count).map(|_| Instruction::CALL(callee.to_owned())));
    instructions.push(Instruction::RET(0));

    function(entry, 1, instructions, HashMap::new())
}

fn call_loop_with_two_args(entry: &str, callee: &str, call_count: usize) -> VMFunction {
    let mut instructions = Vec::with_capacity(call_count * 5 + 1);
    for _ in 0..call_count {
        instructions.push(Instruction::LDI(0, Value::I64(1)));
        instructions.push(Instruction::PUSHARG(0));
        instructions.push(Instruction::LDI(1, Value::I64(2)));
        instructions.push(Instruction::PUSHARG(1));
        instructions.push(Instruction::CALL(callee.to_owned()));
    }
    instructions.push(Instruction::RET(0));

    function(entry, 2, instructions, HashMap::new())
}

fn array_push_program(operation_count: usize) -> VMFunction {
    let mut instructions = Vec::with_capacity(2 + operation_count * 4 + 1);
    instructions.push(Instruction::CALL("create_array".to_owned()));
    instructions.push(Instruction::MOV(1, 0));

    for value in 0..operation_count {
        instructions.push(Instruction::PUSHARG(1));
        instructions.push(Instruction::LDI(2, Value::I64(value as i64)));
        instructions.push(Instruction::PUSHARG(2));
        instructions.push(Instruction::CALL("array_push".to_owned()));
    }

    instructions.push(Instruction::RET(1));
    function("array_push_loop", 3, instructions, HashMap::new())
}

fn object_set_program(operation_count: usize) -> VMFunction {
    let mut instructions = Vec::with_capacity(2 + operation_count * 6 + 1);
    instructions.push(Instruction::CALL("create_object".to_owned()));
    instructions.push(Instruction::MOV(1, 0));

    for value in 0..operation_count {
        instructions.push(Instruction::PUSHARG(1));
        instructions.push(Instruction::LDI(2, Value::String(format!("field_{value}"))));
        instructions.push(Instruction::PUSHARG(2));
        instructions.push(Instruction::LDI(3, Value::I64(value as i64)));
        instructions.push(Instruction::PUSHARG(3));
        instructions.push(Instruction::CALL("set_field".to_owned()));
    }

    instructions.push(Instruction::RET(1));
    function("object_set_loop", 4, instructions, HashMap::new())
}

fn clear_register_copy_many(operation_count: usize) -> VMFunction {
    let mut instructions = Vec::with_capacity(operation_count + 2);
    instructions.push(Instruction::LDI(0, Value::I64(7)));
    instructions.extend((1..=operation_count).map(|dest| Instruction::MOV(dest, 0)));
    instructions.push(Instruction::RET(0));

    function(
        "clear_register_copy_many",
        operation_count + 1,
        instructions,
        HashMap::new(),
    )
}

fn clear_to_secret_many(operation_count: usize) -> VMFunction {
    let mut instructions = Vec::with_capacity(operation_count + 2);
    instructions.push(Instruction::LDI(0, Value::I64(7)));
    instructions.extend((1..=operation_count).map(|dest| Instruction::MOV(dest, 0)));
    instructions.push(Instruction::RET(0));

    function(
        "clear_to_secret_many",
        operation_count + 1,
        instructions,
        HashMap::new(),
    )
}

fn secret_register_copy_many(operation_count: usize) -> VMFunction {
    let mut instructions = Vec::with_capacity(operation_count + 2);
    instructions.push(Instruction::LDI(1, Value::I64(7)));
    instructions.extend((0..operation_count).map(|index| Instruction::MOV(index + 2, 1)));
    instructions.push(Instruction::RET(0));

    function(
        "secret_register_copy_many",
        operation_count + 2,
        instructions,
        HashMap::new(),
    )
}

fn secret_to_clear_many(operation_count: usize) -> VMFunction {
    let secret_register = operation_count;
    let mut instructions = Vec::with_capacity(operation_count + 2);
    instructions.push(Instruction::LDI(secret_register, Value::I64(7)));
    instructions.extend((0..operation_count).map(|dest| Instruction::MOV(dest, secret_register)));
    instructions.push(Instruction::RET(0));

    function(
        "secret_to_clear_many",
        operation_count + 1,
        instructions,
        HashMap::new(),
    )
}

fn async_share_roundtrip_program(name: &str, clear_value: i64) -> VMFunction {
    function(
        name,
        1,
        vec![
            Instruction::LDI(0, Value::I64(clear_value)),
            Instruction::PUSHARG(0),
            Instruction::CALL("Share.from_clear".to_owned()),
            Instruction::PUSHARG(0),
            Instruction::CALL("Share.open".to_owned()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    )
}

fn async_roundtrip_vm(
    entry_count: usize,
    engine: Arc<dyn MpcEngine>,
) -> (VirtualMachine, Vec<String>) {
    let names = (0..entry_count)
        .map(|index| format!("async_roundtrip_{index}"))
        .collect::<Vec<_>>();
    let functions = names
        .iter()
        .enumerate()
        .map(|(index, name)| async_share_roundtrip_program(name, index as i64));

    let mut vm = vm_with(functions);
    vm.set_mpc_engine(engine);
    (vm, names)
}

fn configure(group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>) {
    group.measurement_time(Duration::from_secs(3));
    group.sample_size(50);
}

fn configure_long_diagnostic(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
) {
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(10);
}

fn bench_instruction_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("instruction_throughput");
    configure(&mut group);

    for operation_count in INSTRUCTION_COUNTS {
        group.throughput(Throughput::Elements(operation_count as u64));

        let mut vm = warm(vm_with([add_chain(operation_count)]), "add_chain");
        group.bench_with_input(
            BenchmarkId::new("clear_add_chain", operation_count),
            &operation_count,
            |b, _| b.iter(|| black_box(vm.execute("add_chain").unwrap())),
        );

        let mut vm = warm(vm_with([mov_chain(operation_count)]), "mov_chain");
        group.bench_with_input(
            BenchmarkId::new("register_mov_chain", operation_count),
            &operation_count,
            |b, _| b.iter(|| black_box(vm.execute("mov_chain").unwrap())),
        );

        let mut vm = warm(vm_with([branch_loop(operation_count)]), "branch_loop");
        group.bench_with_input(
            BenchmarkId::new("compare_branch_loop", operation_count),
            &operation_count,
            |b, _| b.iter(|| black_box(vm.execute("branch_loop").unwrap())),
        );
    }

    group.finish();
}

fn bench_dispatch_diagnostics(c: &mut Criterion) {
    let mut group = c.benchmark_group("dispatch_diagnostics");
    configure_long_diagnostic(&mut group);
    group.throughput(Throughput::Elements(LONG_DIAGNOSTIC_COUNT as u64));

    let mut vm = warm(vm_with([nop_loop(LONG_DIAGNOSTIC_COUNT)]), "nop_loop");
    group.bench_function("nop_loop_controlled/10000000", |b| {
        b.iter(|| black_box(vm.execute("nop_loop").unwrap()))
    });

    let mut vm = warm(
        vm_with([cmp_read_loop(LONG_DIAGNOSTIC_COUNT)]),
        "cmp_read_loop",
    );
    group.bench_function("cmp_read_loop_controlled/10000000", |b| {
        b.iter(|| black_box(vm.execute("cmp_read_loop").unwrap()))
    });

    group.finish();
}

fn bench_straight_line_diagnostics(c: &mut Criterion) {
    let mut group = c.benchmark_group("straight_line_diagnostics");
    configure_long_diagnostic(&mut group);
    group.throughput(Throughput::Elements(STRAIGHT_LINE_COUNT as u64));

    {
        let mut vm = warm(vm_with([straight_nop(STRAIGHT_LINE_COUNT)]), "straight_nop");
        group.bench_function("straight_nop_10M", |b| {
            b.iter(|| black_box(vm.execute("straight_nop").unwrap()))
        });
    }

    {
        let mut vm = warm(vm_with([straight_mov(STRAIGHT_LINE_COUNT)]), "straight_mov");
        group.bench_function("straight_mov_10M", |b| {
            b.iter(|| black_box(vm.execute("straight_mov").unwrap()))
        });
    }

    {
        let mut vm = warm(vm_with([straight_add(STRAIGHT_LINE_COUNT)]), "straight_add");
        group.bench_function("straight_add_10M", |b| {
            b.iter(|| black_box(vm.execute("straight_add").unwrap()))
        });
    }

    group.finish();
}

fn bench_register_path_diagnostics(c: &mut Criterion) {
    let mut group = c.benchmark_group("register_path_diagnostics");
    configure_long_diagnostic(&mut group);
    group.throughput(Throughput::Elements(STRAIGHT_LINE_COUNT as u64));

    {
        let mut vm = warm(
            vm_with([straight_write_const(STRAIGHT_LINE_COUNT)]),
            "straight_write_const",
        );
        group.bench_function("write_const_10M", |b| {
            b.iter(|| black_box(vm.execute("straight_write_const").unwrap()))
        });
    }

    {
        let mut vm = warm(
            vm_with([straight_cmp_read_only_proxy(STRAIGHT_LINE_COUNT)]),
            "straight_cmp_read_only_proxy",
        );
        group.bench_function("cmp_read_only_proxy_10M", |b| {
            b.iter(|| black_box(vm.execute("straight_cmp_read_only_proxy").unwrap()))
        });
    }

    {
        let mut vm = warm(
            vm_with([straight_mov_distinct(STRAIGHT_LINE_COUNT)]),
            "straight_mov_distinct",
        );
        group.bench_function("mov_r0_r1_10M", |b| {
            b.iter(|| black_box(vm.execute("straight_mov_distinct").unwrap()))
        });
    }

    {
        let mut vm = warm(
            vm_with([straight_add_distinct(STRAIGHT_LINE_COUNT)]),
            "straight_add_distinct",
        );
        group.bench_function("add_r0_r1_r2_10M", |b| {
            b.iter(|| black_box(vm.execute("straight_add_distinct").unwrap()))
        });
    }

    group.finish();
}

fn bench_register_file_diagnostics(c: &mut Criterion) {
    let mut group = c.benchmark_group("register_file_diagnostics");
    configure_long_diagnostic(&mut group);
    group.throughput(Throughput::Elements(LONG_DIAGNOSTIC_COUNT as u64));

    group.bench_function("copy_clear_i64_10M", |b| {
        b.iter_batched(
            || {
                let mut registers = RegisterFile::with_default_layout(2);
                *registers
                    .get_mut(RegisterIndex::new(0))
                    .expect("destination register should exist") = Value::I64(0);
                *registers
                    .get_mut(RegisterIndex::new(1))
                    .expect("source register should exist") = Value::I64(1);
                registers
            },
            |mut registers| {
                let dest = RegisterIndex::new(0);
                let src = RegisterIndex::new(1);
                for _ in 0..LONG_DIAGNOSTIC_COUNT {
                    black_box(registers.copy_clear_value(dest, src));
                }
                black_box(registers)
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_local_instruction_matrix(c: &mut Criterion) {
    let mut group = c.benchmark_group("local_instruction_matrix");
    configure_long_diagnostic(&mut group);
    group.throughput(Throughput::Elements(STRAIGHT_LINE_COUNT as u64));

    macro_rules! bench_straight {
        ($id:literal, $builder:ident, $entry:literal) => {{
            let mut vm = warm(vm_with([$builder(STRAIGHT_LINE_COUNT)]), $entry);
            group.bench_function($id, |b| b.iter(|| black_box(vm.execute($entry).unwrap())));
        }};
    }

    bench_straight!("ldi_i64_10M", straight_write_const, "straight_write_const");
    bench_straight!("ld_stack_10M", straight_load_stack, "straight_load_stack");
    bench_straight!("sub_i64_10M", straight_sub, "straight_sub");
    bench_straight!("mul_i64_10M", straight_mul, "straight_mul");
    bench_straight!("div_i64_10M", straight_div, "straight_div");
    bench_straight!("mod_i64_10M", straight_mod, "straight_mod");
    bench_straight!("and_i64_10M", straight_and, "straight_and");
    bench_straight!("or_i64_10M", straight_or, "straight_or");
    bench_straight!("xor_i64_10M", straight_xor, "straight_xor");
    bench_straight!("not_i64_10M", straight_not, "straight_not");
    bench_straight!("shl_i64_10M", straight_shl, "straight_shl");
    bench_straight!("shr_i64_10M", straight_shr, "straight_shr");

    group.finish();
}

fn bench_stack_instruction_diagnostics(c: &mut Criterion) {
    let mut group = c.benchmark_group("stack_instruction_diagnostics");
    configure(&mut group);
    group.throughput(Throughput::Elements(STACK_DIAGNOSTIC_COUNT as u64));

    {
        let mut vm = warm(
            vm_with([straight_pusharg(STACK_DIAGNOSTIC_COUNT)]),
            "straight_pusharg",
        );
        group.bench_function("pusharg_100k", |b| {
            b.iter(|| black_box(vm.execute("straight_pusharg").unwrap()))
        });
    }

    group.finish();
}

fn bench_mov_path_diagnostics(c: &mut Criterion) {
    let mut group = c.benchmark_group("mov_path_diagnostics");
    configure_long_diagnostic(&mut group);
    group.throughput(Throughput::Elements(STRAIGHT_LINE_COUNT as u64));

    {
        let mut vm = warm(
            vm_with([straight_mov_self_alias(STRAIGHT_LINE_COUNT)]),
            "straight_mov_self_alias",
        );
        group.bench_function("mov_r0_r0_10M", |b| {
            b.iter(|| black_box(vm.execute("straight_mov_self_alias").unwrap()))
        });
    }

    {
        let mut vm = warm(
            vm_with([straight_mov_distinct(STRAIGHT_LINE_COUNT)]),
            "straight_mov_distinct",
        );
        group.bench_function("mov_r0_r1_10M", |b| {
            b.iter(|| black_box(vm.execute("straight_mov_distinct").unwrap()))
        });
    }

    {
        let mut vm = warm(
            vm_with([straight_mov_reverse_adjacent(STRAIGHT_LINE_COUNT)]),
            "straight_mov_reverse_adjacent",
        );
        group.bench_function("mov_r1_r0_10M", |b| {
            b.iter(|| black_box(vm.execute("straight_mov_reverse_adjacent").unwrap()))
        });
    }

    {
        let mut vm = warm(
            vm_with([straight_mov_far_to_low(STRAIGHT_LINE_COUNT)]),
            "straight_mov_far_to_low",
        );
        group.bench_function("mov_r0_r15_10M", |b| {
            b.iter(|| black_box(vm.execute("straight_mov_far_to_low").unwrap()))
        });
    }

    {
        let mut vm = warm(
            vm_with([straight_mov_low_to_far(STRAIGHT_LINE_COUNT)]),
            "straight_mov_low_to_far",
        );
        group.bench_function("mov_r15_r0_10M", |b| {
            b.iter(|| black_box(vm.execute("straight_mov_low_to_far").unwrap()))
        });
    }

    {
        let mut vm = warm(
            vm_with([straight_mov_zero_source(STRAIGHT_LINE_COUNT)]),
            "straight_mov_zero_source",
        );
        group.bench_function("mov_zero_source_10M", |b| {
            b.iter(|| black_box(vm.execute("straight_mov_zero_source").unwrap()))
        });
    }

    {
        let mut vm = warm(
            vm_with([straight_mov_unit_source(STRAIGHT_LINE_COUNT)]),
            "straight_mov_unit_source",
        );
        group.bench_function("mov_unit_source_10M", |b| {
            b.iter(|| black_box(vm.execute("straight_mov_unit_source").unwrap()))
        });
    }

    group.finish();
}

fn bench_branch_prediction_diagnostics(c: &mut Criterion) {
    let mut group = c.benchmark_group("branch_prediction_diagnostics");
    configure_long_diagnostic(&mut group);
    group.throughput(Throughput::Elements(LONG_DIAGNOSTIC_COUNT as u64));

    let mut vm = warm(
        vm_with([branch_always_taken_loop(LONG_DIAGNOSTIC_COUNT)]),
        "branch_always_taken_loop",
    );
    group.bench_function("always_taken/10000000", |b| {
        b.iter(|| black_box(vm.execute("branch_always_taken_loop").unwrap()))
    });

    let mut vm = warm(
        vm_with([branch_never_taken_loop(LONG_DIAGNOSTIC_COUNT)]),
        "branch_never_taken_loop",
    );
    group.bench_function("never_taken/10000000", |b| {
        b.iter(|| black_box(vm.execute("branch_never_taken_loop").unwrap()))
    });

    let mut vm = warm(
        vm_with([branch_alternating_loop(LONG_DIAGNOSTIC_COUNT)]),
        "branch_alternating_loop",
    );
    group.bench_function("alternating/10000000", |b| {
        b.iter(|| black_box(vm.execute("branch_alternating_loop").unwrap()))
    });

    group.finish();
}

fn bench_function_call_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("function_call_throughput");
    configure(&mut group);

    for call_count in CALL_COUNTS {
        group.throughput(Throughput::Elements(call_count as u64));

        let mut vm = warm(
            vm_with([
                vm_noop_target(),
                call_loop("vm_call_loop", "vm_noop", call_count),
            ]),
            "vm_call_loop",
        );
        group.bench_with_input(
            BenchmarkId::new("vm_function_call", call_count),
            &call_count,
            |b, _| b.iter(|| black_box(vm.execute("vm_call_loop").unwrap())),
        );

        let mut vm = warm(
            vm_with([
                vm_add_target(),
                call_loop_with_two_args("vm_call_with_args_loop", "vm_add", call_count),
            ]),
            "vm_call_with_args_loop",
        );
        group.bench_with_input(
            BenchmarkId::new("vm_function_call_with_args", call_count),
            &call_count,
            |b, _| b.iter(|| black_box(vm.execute("vm_call_with_args_loop").unwrap())),
        );

        let mut vm = vm_with([call_loop("foreign_call_loop", "native.noop", call_count)]);
        vm.register_foreign_function("native.noop", |_| Ok(Value::I64(1)));
        let mut vm = warm(vm, "foreign_call_loop");
        group.bench_with_input(
            BenchmarkId::new("foreign_function_call", call_count),
            &call_count,
            |b, _| b.iter(|| black_box(vm.execute("foreign_call_loop").unwrap())),
        );
    }

    group.finish();
}

fn bench_activation_frame_diagnostics(c: &mut Criterion) {
    let mut group = c.benchmark_group("activation_frame_diagnostics");
    configure(&mut group);
    group.throughput(Throughput::Elements(FRAME_DIAGNOSTIC_COUNT as u64));

    let function_name: Arc<str> = Arc::from("callee");
    let layout = RegisterLayout::default();
    let parameters = vec!["x".to_owned(), "y".to_owned()];
    let borrowed_args = vec![Value::I64(1), Value::I64(2)];

    group.bench_function("empty_frame_100k", |b| {
        b.iter(|| {
            for _ in 0..FRAME_DIAGNOSTIC_COUNT {
                black_box(ActivationRecord::for_function(
                    Arc::clone(&function_name),
                    layout,
                    3,
                    Vec::new(),
                    None,
                ));
            }
        })
    });

    group.bench_function("preallocated_empty_frame_100k", |b| {
        b.iter(|| {
            for _ in 0..FRAME_DIAGNOSTIC_COUNT {
                black_box(ActivationRecord::for_function_with_local_capacity(
                    Arc::clone(&function_name),
                    layout,
                    3,
                    Vec::new(),
                    None,
                    parameters.len(),
                ));
            }
        })
    });

    group.bench_function("bind_borrowed_two_args_100k", |b| {
        b.iter(|| {
            for _ in 0..FRAME_DIAGNOSTIC_COUNT {
                let mut record = ActivationRecord::for_function(
                    Arc::clone(&function_name),
                    layout,
                    3,
                    Vec::new(),
                    None,
                );
                record
                    .bind_parameters(&parameters, &borrowed_args)
                    .expect("benchmark arguments should match parameters");
                black_box(record);
            }
        })
    });

    group.bench_function("bind_owned_two_args_100k", |b| {
        b.iter(|| {
            for _ in 0..FRAME_DIAGNOSTIC_COUNT {
                let mut record = ActivationRecord::for_function(
                    Arc::clone(&function_name),
                    layout,
                    3,
                    Vec::new(),
                    None,
                );
                record
                    .bind_owned_parameters(&parameters, vec![Value::I64(1), Value::I64(2)])
                    .expect("benchmark arguments should match parameters");
                black_box(record);
            }
        })
    });

    group.finish();
}

fn bench_hook_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("hook_overhead");
    configure(&mut group);

    for operation_count in INSTRUCTION_COUNTS {
        group.throughput(Throughput::Elements(operation_count as u64));

        let mut vm = warm(vm_with([add_chain(operation_count)]), "add_chain");
        group.bench_with_input(
            BenchmarkId::new("no_hooks", operation_count),
            &operation_count,
            |b, _| b.iter(|| black_box(vm.execute("add_chain").unwrap())),
        );

        let mut vm = vm_with([add_chain(operation_count)]);
        let hook_id = vm.register_hook(|_| true, |_, _| Ok(()), 0);
        assert!(vm.disable_hook(hook_id));
        let mut vm = warm(vm, "add_chain");
        group.bench_with_input(
            BenchmarkId::new("disabled_hook_registered", operation_count),
            &operation_count,
            |b, _| b.iter(|| black_box(vm.execute("add_chain").unwrap())),
        );

        let mut vm = vm_with([add_chain(operation_count)]);
        vm.register_hook(
            |event| matches!(event, HookEvent::BeforeInstructionExecute(_)),
            |_, _| Ok(()),
            0,
        );
        let mut vm = warm(vm, "add_chain");
        group.bench_with_input(
            BenchmarkId::new("enabled_instruction_hook", operation_count),
            &operation_count,
            |b, _| b.iter(|| black_box(vm.execute("add_chain").unwrap())),
        );
    }

    group.finish();
}

fn bench_table_memory_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("table_memory_throughput");
    configure(&mut group);

    for operation_count in TABLE_OPERATION_COUNTS {
        group.throughput(Throughput::Elements(operation_count as u64));

        let template = vm_with([array_push_program(operation_count)]);
        group.bench_with_input(
            BenchmarkId::new("array_push", operation_count),
            &operation_count,
            |b, _| {
                b.iter_batched(
                    || template.try_clone_with_independent_state().unwrap(),
                    |mut vm| black_box(vm.execute("array_push_loop").unwrap()),
                    BatchSize::SmallInput,
                );
            },
        );

        let template = vm_with([object_set_program(operation_count)]);
        group.bench_with_input(
            BenchmarkId::new("object_set_field", operation_count),
            &operation_count,
            |b, _| {
                b.iter_batched(
                    || template.try_clone_with_independent_state().unwrap(),
                    |mut vm| black_box(vm.execute("object_set_loop").unwrap()),
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

fn bench_register_bank_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("register_bank_throughput");
    configure(&mut group);

    for operation_count in REGISTER_BANK_COUNTS {
        group.throughput(Throughput::Elements(operation_count as u64));

        let engine: Arc<dyn MpcEngine> = Arc::new(ImmediateAsyncEngine);
        let mut vm = warm(
            vm_with_register_layout(
                [clear_register_copy_many(operation_count)],
                RegisterLayout::new(operation_count + 1),
                Arc::clone(&engine),
            ),
            "clear_register_copy_many",
        );
        group.bench_with_input(
            BenchmarkId::new("clear_to_clear_many", operation_count),
            &operation_count,
            |b, _| b.iter(|| black_box(vm.execute("clear_register_copy_many").unwrap())),
        );

        let engine: Arc<dyn MpcEngine> = Arc::new(ImmediateAsyncEngine);
        let mut vm = warm(
            vm_with_register_layout(
                [clear_to_secret_many(operation_count)],
                RegisterLayout::new(1),
                Arc::clone(&engine),
            ),
            "clear_to_secret_many",
        );
        group.bench_with_input(
            BenchmarkId::new("clear_to_secret_many", operation_count),
            &operation_count,
            |b, _| b.iter(|| black_box(vm.execute("clear_to_secret_many").unwrap())),
        );

        let engine: Arc<dyn MpcEngine> = Arc::new(ImmediateAsyncEngine);
        let mut vm = warm(
            vm_with_register_layout(
                [secret_register_copy_many(operation_count)],
                RegisterLayout::new(1),
                Arc::clone(&engine),
            ),
            "secret_register_copy_many",
        );
        group.bench_with_input(
            BenchmarkId::new("secret_to_secret_many", operation_count),
            &operation_count,
            |b, _| b.iter(|| black_box(vm.execute("secret_register_copy_many").unwrap())),
        );

        let engine: Arc<dyn MpcEngine> = Arc::new(ImmediateAsyncEngine);
        let mut vm = warm(
            vm_with_register_layout(
                [secret_to_clear_many(operation_count)],
                RegisterLayout::new(operation_count),
                Arc::clone(&engine),
            ),
            "secret_to_clear_many",
        );
        group.bench_with_input(
            BenchmarkId::new("secret_to_clear_many", operation_count),
            &operation_count,
            |b, _| b.iter(|| black_box(vm.execute("secret_to_clear_many").unwrap())),
        );
    }

    group.finish();
}

fn bench_async_effect_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("async_effect_throughput");
    configure(&mut group);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("benchmark runtime should build");
    let async_engine = Arc::new(ImmediateAsyncEngine);
    let runtime_engine: Arc<dyn MpcEngine> = async_engine.clone();

    for entry_count in ASYNC_ENTRY_COUNTS {
        group.throughput(Throughput::Elements(entry_count as u64));
        let (vm, names) = async_roundtrip_vm(entry_count, Arc::clone(&runtime_engine));
        group.bench_with_input(
            BenchmarkId::new("share_from_clear_open_many", entry_count),
            &entry_count,
            |b, _| {
                b.iter(|| {
                    black_box(
                        runtime
                            .block_on(vm.execute_many_async(
                                names.iter().map(String::as_str),
                                async_engine.as_ref(),
                            ))
                            .unwrap(),
                    )
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_instruction_throughput,
    bench_dispatch_diagnostics,
    bench_straight_line_diagnostics,
    bench_register_path_diagnostics,
    bench_register_file_diagnostics,
    bench_local_instruction_matrix,
    bench_stack_instruction_diagnostics,
    bench_mov_path_diagnostics,
    bench_branch_prediction_diagnostics,
    bench_function_call_throughput,
    bench_activation_frame_diagnostics,
    bench_hook_overhead,
    bench_table_memory_throughput,
    bench_register_bank_throughput,
    bench_async_effect_throughput,
);
criterion_main!(benches);
