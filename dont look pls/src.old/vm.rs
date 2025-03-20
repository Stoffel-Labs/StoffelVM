use operations::opcodes::{Decoder, RedOpcode};
use std::collections::HashMap;
use std::rc::Rc;
use std::fmt;
use crate::handlers::{handle_add, handle_and, handle_call, handle_cmp, handle_div, handle_jmp, handle_jmpeq, handle_jmpneq, handle_ld, handle_ldi, handle_mod, handle_mov, handle_mul, handle_not, handle_or, handle_pusharg, handle_ret, handle_shl, handle_shr, handle_sub, handle_xor};

// we know the network topology ahead of time. We stoffel deploy -> generate tomls -> upload to VPS. Bootstrapping trust assumption

// TODO: Support signed numbers, I've been assuming unsigned
const MAX_REGISTERS: usize = 16;

// Function definition structure. Idea stolen from LUA
#[derive(Debug, Clone)]
pub struct Function {
    pub bytecode: Vec<u8>,
    pub param_count: usize,
    pub local_count: usize,
    pub entry_point: usize,
}

// Activation record for function calls. Idea stolen from LUA
#[derive(Debug)]
pub struct ActivationRecord {
    pub function_id: usize,
    pub locals: Vec<Register>,
    pub local_registers: [Register; MAX_REGISTERS],
    pub return_addr: usize,
    pub base_register: usize,
}

// Object types supported by the Virtual Machine
#[derive(Debug, Clone, PartialEq)]
pub enum ObjectType {
    Struct,
    Array,
    String,
    Raw, // For backward compatibility with existing raw byte storage idrk if needed though
}

// Field definition for struct types
#[derive(Debug, Clone)]
pub struct FieldDef {
    name: String,
    offset: usize,
    size: usize,
    field_type: ObjectType,
}

// Register types to distinguish between clear and secret data
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RegisterType {
    Clear,
    Secret,
}

impl fmt::Display for RegisterType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", if *self == RegisterType::Clear { "Clear" } else { "Secret" })
    }
}

impl RegisterType {
    pub fn identify_register_type(a: RegisterType, b: RegisterType) -> RegisterType {
        match (a, b) {
            (RegisterType::Clear, RegisterType::Clear) => RegisterType::Clear,
            (RegisterType::Secret, _) => RegisterType::Secret,
            (_, RegisterType::Secret) => RegisterType::Secret,
        }
    }
}

#[derive(Debug)]
pub enum MPCOperationState {
    Ready,
    InProgress,
    Completed,
    Failed(String),
}

#[derive(Debug, Clone)]
#[derive(Copy)]
pub struct Register {
    pub value: u64,
    pub reg_type: RegisterType,
}

#[derive(Debug, Clone)]
pub struct ObjectEntry {
    data: Vec<u8>,
    obj_type: ObjectType,
    register_type: RegisterType,
    ref_count: usize, // TODO: actually implement the reference counting and figure out how to avoid cyclic stuff
    metadata: Option<Vec<FieldDef>>, // For struct type metadata
}

// TODO: remove the scuffed impl
// TODO: We need to validate that the provided program is correctly formed 😭
pub struct VM {
    decoder: Decoder,
    // Add function table and activation records. Idea stolen from LUA.
    // TODO: think through how this actually is going to work in terms of compiled program format
    function_table: HashMap<usize, Function>,
    pub(crate) activation_records: Vec<ActivationRecord>,
    current_activation_record: Option<usize>,
    next_function_id: usize,
    pending_arguments: Vec<Register>,
    // Register files TODO: (unbounded amount for now probably should bound it? Need to read more)
    registers: [Register; MAX_REGISTERS],

    // Program counter and VM status
    pub(crate) program_counter: usize,
    running: bool,

    // MPC Operation state
    // Idk if we actually need/want this but I put it just in case!
    mpc_state: Option<MPCOperationState>,
    // Object table for complex data structures
    object_table: HashMap<usize, ObjectEntry>,
    next_object_id: usize,

    // Actual program's bytecode.
    // TODO: Discuss with Mikerah if we are going to support multiple programs concurrently running? Could enable advanced use cases
    program: Option<Rc<Vec<u8>>>,
}

impl VM {
    pub fn new() -> Self {
        let mut vm = VM {
            decoder: Decoder::new(),
            function_table: HashMap::new(),
            activation_records: Vec::new(),
            current_activation_record: None,
            next_function_id: 0,
            pending_arguments: Vec::new(),
            registers: [Register { value: 0, reg_type: RegisterType::Clear }; MAX_REGISTERS],
            program_counter: 0,
            running: false,
            mpc_state: None,
            object_table: HashMap::new(),
            next_object_id: 0,
            program: None,
        };
        
        // TODO: Bottom half are clear, top half are secret
        
        // we're making half clear / half secret because it is implicit about whether to reveal or hide values. By having two sets of typed registers we are explicit about when we want to reveal/hide by moving between the register types
        // Agreed upon  Feb 3rd, 2025
        // Initialize registers
        for i in 0..MAX_REGISTERS {
            if i > (MAX_REGISTERS / 2)   {
                vm.registers[i].reg_type = RegisterType::Secret;
            }
        }
        vm
    }

    // Helper methods to access the current activation record
    pub fn get_current_activation_record(&self) -> Option<&ActivationRecord> {
        self.current_activation_record.and_then(|idx| self.activation_records.get(idx))
    }

    pub fn get_current_activation_record_mut(&mut self) -> Option<&mut ActivationRecord> {
        if let Some(idx) = self.current_activation_record {
            self.activation_records.get_mut(idx)
        } else {
            None
        }
    }

    pub fn get_current_activation_record_index(&self) -> Option<usize> {
        self.current_activation_record
    }

    // Function management methods
    pub fn register_function(
        &mut self,
        bytecode: Vec<u8>,
        param_count: usize,
        local_count: usize,
        entry_point: usize,
    ) -> usize {
        let id = self.next_function_id;
        self.function_table.insert(
            id,
            Function {
                bytecode,
                param_count,
                local_count,
                entry_point,
            },
        );
        self.next_function_id += 1;
        id
    }

    pub fn call_function(
        &mut self,
        function_id: usize
    ) -> Result<(), &'static str> {
        let function = self
            .function_table
            .get(&function_id)
            .ok_or("Function not found")?;

        if self.pending_arguments.len() != function.param_count {
            return Err("Invalid argument count for function call");
        }

        // Create new activation record
        let return_addr = self.program_counter;
        let base_register = self.registers.len();

        // Initialize locals including parameters
        let mut locals = self.pending_arguments.clone();
        locals.resize(
            function.local_count + function.param_count,
            Register {
                value: 0,
                reg_type: RegisterType::Clear,
            },
        );

        self.activation_records.push(ActivationRecord {
            function_id,
            locals,
            local_registers: self.registers.clone(),
            return_addr,
            base_register,
        });

        // Set the current activation record to the newly pushed one
        self.current_activation_record = Some(self.activation_records.len() - 1);

        // Initialize registers for function execution
        self.initialize_function_registers(function_id)?;

        // Clear pending arguments after creating the activation record
        self.pending_arguments.clear();

        // Jump to function entry point
        self.program_counter = function.entry_point;
        Ok(())
    }

    // Initialize registers for function execution
    fn initialize_function_registers(&mut self, function_id: usize) -> Result<(), &'static str> {
        let function = self
            .function_table
            .get(&function_id)
            .ok_or("Function not found")?;
        
        // Clear all registers first
        for i in 0..MAX_REGISTERS {
            self.registers[i] = Register {
                value: 0,
                reg_type: RegisterType::Clear,
            };
        }
        
        // Copy function arguments from the activation record to registers
        if let Some(record_idx) = self.current_activation_record {
            let record = &self.activation_records[record_idx];
            
            // Copy parameters to registers
            for (i, param) in record.locals.iter().enumerate().take(function.param_count) {
                self.registers[i] = param.clone();
            }
        }
        
        Ok(())
    }

    pub fn return_from_function(&mut self, return_value: Option<Register>) -> Result<(), &'static str> {
        // Store the return value in register 0 of the caller if provided
        if let Some(return_reg) = return_value {
            self.set_register(0, return_reg.value, return_reg.reg_type)?;
        }
        
        // Store the previous activation record index before popping
        let previous_index = if self.activation_records.len() > 1 {
            Some(self.activation_records.len() - 2)
        } else {
            None
        };
        
        if let Some(mut record) = self.activation_records.pop() {
            // Save return value before restoring registers
            let saved_return_value = if let Some(ref ret_val) = return_value {
                Some(ret_val.clone())
            } else {
                None
            };
            
            // Restore the caller's registers
            self.registers = record.local_registers;
            self.current_activation_record = previous_index;
            
            // Restore the program counter to return address
            self.program_counter = record.return_addr;
            Ok(())
        } else {
            Err("No function to return from")
        }
    }

    pub fn push_argument(&mut self, reg: Register) -> Result<(), &'static str> {
        // Add the register to the pending arguments list
        self.pending_arguments.push(reg);
        Ok(())
    }

    pub fn get_pending_arguments_count(&self) -> usize {
        self.pending_arguments.len()
    }

    pub fn load_program(&mut self, program: Vec<u8>) {
        // FIXME: Add a way to validate that the program is correctly assembled e.g: no invalid op codes.
        self.program = Some(Rc::new(program));
        self.decoder.load_program(self.program.clone().unwrap());
        self.program_counter = 0;
    }

    pub fn allocate_object(
        &mut self,
        data: Vec<u8>,
        obj_type: ObjectType,
        register_type: RegisterType,
        metadata: Option<Vec<FieldDef>>,
    ) -> usize {
        let id = self.next_object_id;
        self.object_table.insert(
            id,
            ObjectEntry {
                data,
                register_type,
                obj_type,
                ref_count: 1,
                metadata,
            },
        );
        self.next_object_id += 1;
        id
    }

    pub fn get_object(&self, id: usize) -> Option<&ObjectEntry> {
        self.object_table.get(&id)
    }

    //TODO: figure out how de-allocating an object in the object table should work/look like

    pub fn get_register(&self, index: usize) -> Option<&Register> {
        self.registers.get(index)
    }

    pub fn get_register_mut(&mut self, index: usize) -> Option<&mut Register> {
        self.registers.get_mut(index)
    }

    pub fn set_register(
        &mut self,
        index: usize,
        value: u64,
        new_type: RegisterType,
    ) -> Result<(), &'static str> {
        if index >= MAX_REGISTERS {
            return Err("Register index out of bounds");
        }

        let register = self.get_register_mut(index).unwrap();
        register.reg_type = new_type;
        register.value = value;

        Ok(())
    }

    pub fn is_secret_op(&self, op1_idx: usize, op2_idx: usize) -> bool {
        // If either register doing the operation are secret this is an online thing!
        if self.registers[op1_idx].reg_type == RegisterType::Secret
            || self.registers[op2_idx].reg_type == RegisterType::Secret
        {
            return true;
        }
        false
    }

    pub async fn perform_arithmetic_op(
        &mut self,
        op1_idx: usize,
        op2_idx: usize,
        dest_idx: usize,
        operation: impl Fn(u64, u64) -> u64,
    ) -> Result<(), &'static str> {
        // TODO: redo this because it straight up doesn't work for MPC with the way this is structured
        
        // If either operand is secret, we need to do MPC so async tokio ig
        // if self.is_secret_op(op1_idx, op2_idx) {
        //     self.mpc_state = Some(MPCOperationState::InProgress);
        // 
        //     // tokio::task::yield_now().await;
        // 
        //     // Figure out with Mikerah how we're integrating the network stack
        //     // TODO: fix this error bc idk what I was doing tbh
        //     if let Some(MPCOperationState::Failed(err)) = &self.mpc_state {
        //         return Err(err);
        //     }
        //     self.mpc_state = Some(MPCOperationState::Completed);
        //     Ok(())
        // } else {
        let op1 = self.registers[op1_idx];
        let op2 = self.registers[op2_idx];

        let result_value = operation(op1.value, op2.value);

        // TODO: rework how this bit works bc it is mad scuffed. We need to change the register type as well but right now we just do the truth table mapping
        let result_type = RegisterType::identify_register_type(op1.reg_type, op2.reg_type);

        self.set_register(dest_idx, result_value, result_type)?;

        Ok(())
        // }
    }

    // Main execution loop
    pub async fn run(&mut self) {
        self.running = true;
        while self.running && self.program_counter < self.program.as_ref().unwrap().len() {
            if let Err(e) = self.step().await {
                println!("VM Error: {}", e);
                self.running = false;
            }
        }
    }

    // Fetch, decode, execute :O
    async fn step(&mut self) -> Result<(), &'static str> {
        let opcode = self.decoder.next_opcode();
        let program = self.program.as_ref().unwrap();

        // TODO: Finish implementing everything, tbh probably need to separate opcode implementations to their own files to keep things tidy
        // TODO: Instead of clear and secret opcodes change it so that the runtime handles all that
        // TODO: Add support for conditional / function calls bc that is going to be important
        match opcode {
            None => {
                self.running = false;
                println!("Reached end of program");
                Ok(())
            }
            Some(opcode) => {
                match opcode {
                    RedOpcode::LD { source_idx, target_idx } => {
                        handle_ld(self, source_idx, target_idx).await;
                        Ok(())
                    }
                    RedOpcode::LDI { target_idx, immediate_value } => {
                        handle_ldi(self, target_idx, immediate_value).await;
                        Ok(())
                    },
                    RedOpcode::MOV { source_idx, target_idx } => {
                        handle_mov(self, source_idx, target_idx).await;
                        Ok(())
                    }
                    RedOpcode::ADD { source1_idx, source2_idx, target_idx } => {
                        handle_add(self, source1_idx, source2_idx, target_idx).await;
                        Ok(())
                    }
                    RedOpcode::SUB { source1_idx, source2_idx, target_idx } => {
                        handle_sub(self, source1_idx, source2_idx, target_idx).await;
                        Ok(())
                    }
                    RedOpcode::MUL { source1_idx, source2_idx, target_idx } => {
                        handle_mul(self, source1_idx, source2_idx, target_idx).await;
                        Ok(())
                    }
                    RedOpcode::DIV { source1_idx, source2_idx, target_idx } => {
                        handle_div(self, source1_idx, source2_idx, target_idx).await;
                        Ok(())
                    }
                    RedOpcode::MOD { source1_idx, source2_idx, target_idx } => {
                        handle_mod(self, source1_idx, source2_idx, target_idx).await;
                        Ok(())
                    }
                    RedOpcode::AND { source1_idx, source2_idx, target_idx } => {
                        handle_and(self, source1_idx, source2_idx, target_idx).await;
                        Ok(())
                    }
                    RedOpcode::OR { source1_idx, source2_idx, target_idx } => {
                        handle_or(self, source1_idx, source2_idx, target_idx).await;
                        Ok(())
                    }
                    RedOpcode::XOR { source1_idx, source2_idx, target_idx } => {
                        handle_xor(self, source1_idx, source2_idx, target_idx).await;
                        Ok(())
                    }
                    RedOpcode::NOT { source_idx, target_idx } => {
                        handle_not(self, source_idx, target_idx).await;
                        Ok(())
                    }
                    RedOpcode::SHL { source1_idx, source2_idx, target_idx } => {
                        handle_shl(self, source1_idx, source2_idx, target_idx).await;
                        Ok(())
                    }
                    RedOpcode::SHR { source1_idx, source2_idx, target_idx } => {
                        handle_shr(self, source1_idx, source2_idx, target_idx).await;
                        Ok(())
                    }
                    RedOpcode::JMP { target_idx } => {
                        handle_jmp(self, target_idx).await;
                        Ok(())
                    }
                    RedOpcode::JMPEQ { target_idx } => {
                        handle_jmpeq(self, target_idx).await;
                        Ok(())
                    }
                    RedOpcode::JMPNEQ { target_idx } => {
                        handle_jmpneq(self, target_idx).await;
                        Ok(())
                    }
                    RedOpcode::CALL { target_idx } => {
                        let result = self.call_function(target_idx);
                        result?;
                        Ok(())
                    }
                    RedOpcode::RET { source_idx } => {
                        let return_value = self.get_register(source_idx).copied();
                        self.return_from_function(return_value)?;
                        Ok(())
                    },
                    RedOpcode::PUSHARG { source_idx } => {
                        handle_pusharg(self, source_idx).await?;
                        Ok(())
                    }
                    RedOpcode::CMP { source1_idx, source2_idx } => {
                        handle_cmp(self, source1_idx, source2_idx).await;
                        Ok(())
                    }
                    _ => {
                        Err("Unknown opcode")
                    }
                }
            }
        }
    }
}

// Helper function to print register state for debugging
pub fn print_registers(vm: &VM) {
    println!("Register state:");
    for i in 0..MAX_REGISTERS {
        if let Some(reg) = vm.get_register(i) {
            println!("R{}: {} ({})", i, reg.value, reg.reg_type);
        }
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_arithmetic_program() {
        let mut vm = VM::new();

        let program = vec![0x01, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 3, 0, 0, 0, 0, 0, 0, 0, 0x03, 0, 1, 2];

        vm.load_program(program);
        vm.run().await;

        assert_eq!(vm.get_register(2).unwrap().value, 8);
    }

    #[tokio::test]
    async fn test_simple_function_call() {
        let mut vm = VM::new();

        // Create a function that adds two numbers
        // Function code: add two numbers and return result in r0
        let add_function = vec![
            0x03, 0, 1, 0,  // ADD r0, r1, r0 (add first two arguments, store in r0)
            0x12, 0         // RET r0 (return value in r0)
        ];

        // Register the function with 2 parameters
        let function_id = vm.register_function(add_function, 2, 0, 0);

        // Main program
        let program = vec![
            0x01, 0, 5, 0, 0, 0, 0, 0, 0, 0,  // LDI r0, 5
            0x01, 1, 3, 0, 0, 0, 0, 0, 0, 0,  // LDI r1, 3
            0x13, 0,                          // PUSHARG r0 (push 5)
            0x13, 1,                          // PUSHARG r1 (push 3)
            0x11, function_id as u8,          // CALL function_id
            // After return, result should be in r0
        ];

        vm.load_program(program);
        vm.run().await;

        // Check if the result is correct (5 + 3 = 8)
        assert_eq!(vm.get_register(0).unwrap().value, 8);
    }

    #[tokio::test]
    async fn test_nested_function_calls() {
        let mut vm = VM::new();

        // Function 1: doubles a number
        let double_function = vec![
            0x03, 0, 0, 0,  // ADD r0, r0, r0 (double the input)
            0x12, 0         // RET r0
        ];

        // Function 2: adds 10 to a number
        let add_ten_function = vec![
            0x01, 1, 10, 0, 0, 0, 0, 0, 0, 0,  // LDI r1, 10
            0x03, 0, 1, 0,                     // ADD r0, r1, r0
            0x12, 0                            // RET r0
        ];

        // Register both functions
        let double_id = vm.register_function(double_function, 1, 1, 0);
        let add_ten_id = vm.register_function(add_ten_function, 1, 1, 0);

        // Main program: calculate (5*2)+10
        let program = vec![
            0x01, 0, 5, 0, 0, 0, 0, 0, 0, 0,  // LDI r0, 5
            0x13, 0,                          // PUSHARG r0 (push 5)
            0x11, double_id as u8,            // CALL double_function
            // r0 now contains 10
            0x13, 0,                          // PUSHARG r0 (push 10)
            0x11, add_ten_id as u8,           // CALL add_ten_function
            // r0 now contains 20
        ];

        vm.load_program(program);
        vm.run().await;

        // Check if the result is correct ((5*2)+10 = 20)
        assert_eq!(vm.get_register(0).unwrap().value, 20);
    }

    #[tokio::test]
    async fn test_function_with_multiple_arguments() {
        let mut vm = VM::new();

        // Function that multiplies three numbers
        let multiply_function = vec![
            0x05, 0, 1, 0,  // MUL r0, r1, r0 (multiply first two args)
            0x05, 0, 2, 0,  // MUL r0, r2, r0 (multiply by third arg)
            0x12, 0         // RET r0
        ];

        // Register the function with 3 parameters
        let function_id = vm.register_function(multiply_function, 3, 0, 0);

        // Main program
        let program = vec![
            0x01, 0, 2, 0, 0, 0, 0, 0, 0, 0,  // LDI r0, 2
            0x01, 1, 3, 0, 0, 0, 0, 0, 0, 0,  // LDI r1, 3
            0x01, 2, 4, 0, 0, 0, 0, 0, 0, 0,  // LDI r2, 4
            0x13, 0,                          // PUSHARG r0 (push 2)
            0x13, 1,                          // PUSHARG r1 (push 3)
            0x13, 2,                          // PUSHARG r2 (push 4)
            0x11, function_id as u8,          // CALL function_id
            // After return, result should be in r0
        ];

        vm.load_program(program);
        vm.run().await;

        // Check if the result is correct (2 * 3 * 4 = 24)
        assert_eq!(vm.get_register(0).unwrap().value, 24);
    }

    #[tokio::test]
    async fn test_register_preservation_across_calls() {
        let mut vm = VM::new();

        // Function that adds 1 to its argument
        let increment_function = vec![
            0x01, 1, 1, 0, 0, 0, 0, 0, 0, 0,  // LDI r1, 1
            0x03, 0, 1, 0,                    // ADD r0, r1, r0
            0x12, 0                           // RET r0
        ];

        // Register the function
        let function_id = vm.register_function(increment_function, 1, 1, 0);

        // Main program
        let program = vec![
            0x01, 0, 5, 0, 0, 0, 0, 0, 0, 0,  // LDI r0, 5
            0x01, 1, 10, 0, 0, 0, 0, 0, 0, 0, // LDI r1, 10
            0x13, 0,                          // PUSHARG r0 (push 5)
            0x11, function_id as u8,          // CALL function_id
            // r0 now contains 6, r1 should still be 10
        ];

        vm.load_program(program);
        vm.run().await;

        // Check if r0 has the correct return value
        assert_eq!(vm.get_register(0).unwrap().value, 6);

        // Check if r1 was preserved
        assert_eq!(vm.get_register(1).unwrap().value, 10);
    }

    #[tokio::test]
    async fn test_current_activation_record_tracking() {
        let mut vm = VM::new();

        // Create a function that adds two numbers
        let add_function = vec![
            0x03, 0, 1, 0,  // ADD r0, r1, r0
            0x12, 0         // RET r0
        ];

        let function_id = vm.register_function(add_function, 2, 0, 0);

        // Main program
        let program = vec![
            0x01, 0, 5, 0, 0, 0, 0, 0, 0, 0,  // LDI r0, 5
            0x01, 1, 3, 0, 0, 0, 0, 0, 0, 0,  // LDI r1, 3
            0x13, 0,                          // PUSHARG r0
            0x13, 1,                          // PUSHARG r1
            0x11, function_id as u8,          // CALL function_id
        ];

        vm.load_program(program);
        vm.run().await;

        // After the program completes, there should be no current activation record
        assert_eq!(vm.get_current_activation_record_index(), None);
    }

    #[tokio::test]
    async fn test_register_isolation_in_functions() {
        let mut vm = VM::new();

        // Function that modifies multiple registers
        let modify_registers_function = vec![
            0x01, 0, 100, 0, 0, 0, 0, 0, 0, 0,  // LDI r0, 100
            0x01, 1, 200, 0, 0, 0, 0, 0, 0, 0,  // LDI r1, 200
            0x01, 2, 44, 1, 0, 0, 0, 0, 0, 0,   // LDI r2, 300 
            0x12, 0                            // RET r0
        ];

        // Register the function
        let function_id = vm.register_function(modify_registers_function, 1, 3, 0);

        // Main program
        let program = vec![
            0x01, 0, 5, 0, 0, 0, 0, 0, 0, 0,    // LDI r0, 5
            0x01, 1, 10, 0, 0, 0, 0, 0, 0, 0,   // LDI r1, 10
            0x01, 2, 15, 0, 0, 0, 0, 0, 0, 0,   // LDI r2, 15
            0x13, 0,                           // PUSHARG r0
            0x11, function_id as u8,           // CALL function_id
            // After return, r0 should contain 100 (return value)
            // But r1 and r2 should still be 10 and 15
        ];

        vm.load_program(program);
        vm.run().await;

        // Check if r0 has the return value from the function
        assert_eq!(vm.get_register(0).unwrap().value, 100);

        // Check if r1 and r2 were preserved (not affected by function's modifications)
        assert_eq!(vm.get_register(1).unwrap().value, 10);
        assert_eq!(vm.get_register(2).unwrap().value, 15);
    }

    #[tokio::test]
    async fn test_nested_function_register_isolation() {
        // TODO: Implement a test for nested function calls
        // to ensure register isolation works correctly
        // when functions call other functions
    }

    #[test]
    fn test_register_bounds() {
        let mut vm = VM::new();

        // Test valid register access
        assert!(vm.set_register(31, 42, RegisterType::Clear).is_ok());

        // Test invalid register access
        assert!(vm.set_register(32, 42, RegisterType::Clear).is_err());
    }

    #[test]
    fn test_register_operations() {
        let mut vm = VM::new();

        // Test clear register
        vm.set_register(0, 42, RegisterType::Clear).unwrap();
        let reg = vm.get_register(0).unwrap();
        assert_eq!(reg.value, 42);
        assert_eq!(reg.reg_type, RegisterType::Clear);

        // Test secret register
        vm.set_register(0, 100, RegisterType::Secret).unwrap();
        let reg = vm.get_register(0).unwrap();
        assert_eq!(reg.value, 100);
        assert_eq!(reg.reg_type, RegisterType::Secret);
    }

    #[test]
    fn test_object_table() {
        let mut vm = VM::new();

        let data = vec![1, 2, 3, 4];
        let obj_id = vm.allocate_object(data.clone(), ObjectType::Raw, RegisterType::Clear, None);

        let obj = vm.get_object(obj_id).unwrap();
        assert_eq!(obj.data, data);
        assert_eq!(obj.register_type, RegisterType::Clear);
        assert_eq!(obj.obj_type, ObjectType::Raw);
        assert_eq!(obj.ref_count, 1);
    }

    #[test]
    fn test_struct_object() {
        let mut vm = VM::new();

        // Create a simple struct with two fields
        let fields = vec![
            FieldDef {
                name: "field1".to_string(),
                offset: 0,
                size: 8,
                field_type: ObjectType::Raw,
            },
            FieldDef {
                name: "field2".to_string(),
                offset: 8,
                size: 8,
                field_type: ObjectType::Raw,
            },
        ];

        let data = vec![0; 16]; // 16 bytes for two 8-byte fields
        let obj_id =
            vm.allocate_object(data, ObjectType::Struct, RegisterType::Clear, Some(fields));

        let obj = vm.get_object(obj_id).unwrap();
        assert_eq!(obj.obj_type, ObjectType::Struct);
        assert!(obj.metadata.is_some());
        assert_eq!(obj.metadata.as_ref().unwrap().len(), 2);
    }
}
