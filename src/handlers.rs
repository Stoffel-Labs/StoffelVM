use super::operations::opcodes::RedOpcode;
use super::vm::{Register, RegisterType, VM};

// TODO: Move all the handlers into their respective files
pub fn handle_ld(vm: &mut VM, source_idx: usize, target_idx: usize) {
    let source_register = vm.get_register(source_idx).unwrap();
    let value = source_register.value;
    let reg_type = source_register.reg_type;
    vm.set_register(target_idx, value, reg_type).unwrap();
}

pub fn handle_ldi(vm: &mut VM, target_idx: usize, immediate_value: u64) {
    vm.set_register(target_idx, immediate_value, RegisterType::Clear)
        .unwrap();
}

pub fn handle_mov(vm: &mut VM, source_idx: usize, target_idx: usize) {
    let reg = vm.get_register(source_idx).unwrap();

    let value = reg.value;
    let reg_type = reg.reg_type;


    vm.set_register(target_idx, value, reg_type).unwrap();
}

pub async fn handle_add(vm: &mut VM, source1_idx: usize, source2_idx: usize, target_idx: usize) {
    vm.perform_arithmetic_op(source1_idx, source2_idx, target_idx, |a, b| a + b)
        .await.unwrap();
}

pub async fn handle_sub(vm: &mut VM, source1_idx: usize, source2_idx: usize, target_idx: usize) {
    vm.perform_arithmetic_op(source1_idx, source2_idx, target_idx, |a, b| a - b)
        .await.unwrap();
}

pub async fn handle_mul(vm: &mut VM, source1_idx: usize, source2_idx: usize, target_idx: usize) {
    vm.perform_arithmetic_op(source1_idx, source2_idx, target_idx, |a, b| a * b)
        .await.unwrap();
}

pub async fn handle_div(vm: &mut VM, source1_idx: usize, source2_idx: usize, target_idx: usize) {
    vm.perform_arithmetic_op(source1_idx, source2_idx, target_idx, |a, b| a / b)
        .await.unwrap();
}

pub async fn handle_mod(vm: &mut VM, source1_idx: usize, source2_idx: usize, target_idx: usize) {
    vm.perform_arithmetic_op(source1_idx, source2_idx, target_idx, |a, b| a % b)
        .await.unwrap();
}

pub async fn handle_and(vm: &mut VM, source1_idx: usize, source2_idx: usize, target_idx: usize) {
    vm.perform_arithmetic_op(source1_idx, source2_idx, target_idx, |a, b| a & b)
        .await.unwrap();
}

pub async fn handle_or(vm: &mut VM, source1_idx: usize, source2_idx: usize, target_idx: usize) {
    vm.perform_arithmetic_op(source1_idx, source2_idx, target_idx, |a, b| a | b)
        .await.unwrap();
}

pub async fn handle_xor(vm: &mut VM, source1_idx: usize, source2_idx: usize, target_idx: usize) {
    vm.perform_arithmetic_op(source1_idx, source2_idx, target_idx, |a, b| a ^ b)
        .await.unwrap();
}

pub fn handle_not(vm: &mut VM, source_idx: usize, target_idx: usize) {
    let reg = vm.get_register(source_idx).unwrap();

    let value = reg.value;
    let reg_type = reg.reg_type;

    vm.set_register(target_idx, value, reg_type).unwrap();
}

pub fn handle_shl(vm: &mut VM, source1_idx: usize, source2_idx: usize, target_idx: usize) {
    let reg_1 = vm.get_register(source1_idx).unwrap();
    let reg_2 = vm.get_register(source2_idx).unwrap();
    let shift_amount = reg_2.value;
    let value = reg_1.value << shift_amount;
    let reg_type = reg_1.reg_type;
    vm.set_register(target_idx, value, reg_type).unwrap();
}

pub fn handle_shr(vm: &mut VM, source1_idx: usize, source2_idx: usize, target_idx: usize) {
    let reg_1 = vm.get_register(source1_idx).unwrap();
    let reg_2 = vm.get_register(source2_idx).unwrap();

    let shift_amount = reg_2.value;
    let value = reg_1.value >> shift_amount;
    let reg_type = reg_1.reg_type;
    vm.set_register(target_idx, value, reg_type).unwrap();
}

pub fn handle_jmp(vm: &mut VM, target_idx: usize) {
    vm.program_counter = target_idx;
}

pub fn handle_jmpeq(vm: &mut VM, target_idx: usize) {
    // TODO: implement the result of a comparison opcode call
    vm.program_counter = target_idx;
}

pub fn handle_jmpneq(vm: &mut VM, target_idx: usize) {
    // TODO: implement the result of a comparison opcode call
    vm.program_counter = target_idx;
}

pub async fn handle_call(vm: &mut VM, target_idx: usize) {
    vm.call_function(target_idx, vec![]).unwrap();
}

pub fn handle_ret(vm: &mut VM, source_idx: usize) {
    vm.return_from_function().unwrap();
}

pub fn handle_pusharg(vm: &mut VM, source_idx: usize) {
    let reg = vm.get_register(source_idx).unwrap();

    let value = reg.value;
    let reg_type = reg.reg_type;
    if let Some(record) = vm.activation_records.last_mut() {
        record.locals.push(Register { value, reg_type });
    }
}

pub fn handle_store(vm: &mut VM, source_idx: usize) {
    // TODO: Implement memory store operation
}

pub fn handle_cmp(vm: &mut VM, source1_idx: usize, source2_idx: usize) {
    let reg_1 = vm.get_register(source1_idx).unwrap();
    let reg_2 = vm.get_register(source2_idx).unwrap();

    let value1 = reg_1.value;
    let value2 = reg_2.value;
    // TODO: add a dedicated comparison register probably tbh
    // vm.registers[0].value = if value1 == value2 { 1 } else { 0 };
}
