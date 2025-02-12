use operations::opcodes::{Decoder, RedOpcode};
use std::collections::HashMap;
use std::rc::Rc;
use crate::handlers::{handle_add, handle_call, handle_ldi};

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
    next_function_id: usize,
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
            next_function_id: 0,
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
        function_id: usize,
        args: Vec<Register>,
    ) -> Result<(), &'static str> {
        let function = self
            .function_table
            .get(&function_id)
            .ok_or("Function not found")?;

        if args.len() != function.param_count {
            return Err("Invalid argument count");
        }

        // Create new activation record
        let return_addr = self.program_counter;
        let base_register = self.registers.len();

        // Initialize locals including parameters
        let mut locals = args;
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
            return_addr,
            base_register,
        });

        // Jump to function entry point
        self.program_counter = function.entry_point;
        Ok(())
    }

    pub fn return_from_function(&mut self) -> Result<(), &'static str> {
        if let Some(record) = self.activation_records.pop() {
            self.program_counter = record.return_addr;
            Ok(())
        } else {
            Err("No function to return from")
        }
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
        let op1 = self.registers[op1_idx].clone();
        let op2 = self.registers[op2_idx].clone();

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
                    RedOpcode::ADD { source1_idx, source2_idx, target_idx } => {
                        handle_add(self, source1_idx, source2_idx, target_idx).await;
                        Ok(())
                    }
                    RedOpcode::CALL { target_idx } => {
                        handle_call(self, target_idx).await;
                        Ok(())
                    }
                    RedOpcode::RET { source_idx: _ } => {
                        let _ = self.return_from_function();
                        Ok(())
                    },
                    RedOpcode::LDI { target_idx, immediate_value } => {
                        handle_ldi(self, target_idx, immediate_value);
                        Ok(())
                    },
                    _ => {
                        Err("Unknown opcode")
                    }
                }
            }
        }
    }
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

    // #[tokio::test]
    // async fn test_function_call() {
    //     let mut vm = VM::new();
    //
    //     // Register a simple function that adds 1 to register 0
    //     let function_code = vec![
    //         RedOpcode::LDI as u8, 1, 1, 0, 0, 0, 0, 0, 0, 0,    // LDI r1, 1
    //         RedOpcode::ADD as u8, 0, 1, 0,                       // ADD r0, r1, r0
    //         RedOpcode::RET as u8, 0,                             // RET r0
    //     ];
    //
    //     let function_id = vm.register_function(function_code, 1, 2, 0);
    //
    //     // Main program that calls the function
    //     let program = create_test_program(vec![
    //         (RedOpcode::LDI, vec![0, 5, 0, 0, 0, 0, 0, 0, 0]),  // LDI r0, 5
    //         (RedOpcode::CALL, vec![function_id as u8]),          // CALL function_id
    //     ]);
    //
    //     vm.load_program(program);
    //     vm.run().await;
    //
    //     assert_eq!(vm.get_register(0).unwrap().value, 6);
    // }

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

    #[tokio::test]
    async fn test_register_type_propagation() {
        let mut vm = VM::new();

        // Test clear + clear = clear
        vm.set_register(0, 5, RegisterType::Clear).unwrap();
        vm.set_register(1, 3, RegisterType::Clear).unwrap();
        vm.perform_arithmetic_op(0, 1, 2, |a, b| a + b).await.unwrap();
        assert_eq!(
            vm.get_register(2).unwrap().reg_type,
            RegisterType::Clear
        );

        // Test secret + clear = secret
        vm.set_register(3, 5, RegisterType::Secret).unwrap();
        vm.set_register(4, 3, RegisterType::Clear).unwrap();
        vm.perform_arithmetic_op(3, 4, 5, |a, b| a + b).await.unwrap();
        assert_eq!(
            vm.get_register(5).unwrap().reg_type,
            RegisterType::Secret
        );

        // Test clear + secret = secret
        vm.set_register(6, 5, RegisterType::Clear).unwrap();
        vm.set_register(7, 3, RegisterType::Secret).unwrap();
        vm.perform_arithmetic_op(6, 7, 8, |a, b| a + b).await.unwrap();
        assert_eq!(
            vm.get_register(8).unwrap().reg_type,
            RegisterType::Secret
        );

        // Test secret + secret = secret
        vm.set_register(9, 5, RegisterType::Secret).unwrap();
        vm.set_register(10, 3, RegisterType::Secret).unwrap();
        vm.perform_arithmetic_op(9, 10, 11, |a, b| a + b).await.unwrap();
        assert_eq!(
            vm.get_register(11).unwrap().reg_type,
            RegisterType::Secret
        );
    }
}
