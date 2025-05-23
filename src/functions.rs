use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use crate::instructions::Instruction;
use crate::core_types::Value;
use crate::vm_state::VMState;

use crate::instructions::ResolvedInstruction;
use smallvec::SmallVec;

/// VM function definition
#[derive(Clone)]
pub struct VMFunction {
    pub cached_instructions: Option<Vec<Instruction>>,
    pub resolved_instructions: Option<SmallVec<[ResolvedInstruction; 32]>>,
    pub constant_values: Option<SmallVec<[Value; 16]>>,
    pub name: String,
    pub parameters: Vec<String>,
    pub upvalues: Vec<String>,
    pub parent: Option<String>,
    pub register_count: usize,
    pub instructions: Vec<Instruction>,
    pub labels: HashMap<String, usize>,
}

impl VMFunction {
    // Create a new VMFunction with default values for the new fields
    pub fn new(name: String, parameters: Vec<String>, upvalues: Vec<String>, parent: Option<String>, 
               register_count: usize, instructions: Vec<Instruction>, labels: HashMap<String, usize>) -> Self {
        VMFunction {
            cached_instructions: None,
            resolved_instructions: None,
            constant_values: None,
            name,
            parameters,
            upvalues,
            parent,
            register_count,
            instructions,
            labels,
        }
    }

    pub fn cache_instructions(&mut self) {
        if self.cached_instructions.is_none() {
            let cached = self.instructions.clone();
            self.cached_instructions = Some(cached);
        }
    }

    pub fn resolve_instructions(&mut self) {
        if self.resolved_instructions.is_some() {
            return; // Already resolved
        }

        let mut resolved = SmallVec::<[ResolvedInstruction; 32]>::new();
        let mut constants = SmallVec::<[Value; 16]>::new();
        let mut const_indices = HashMap::new();

        // Resolve label references to instruction indices
        let mut label_indices = HashMap::new();
        for (label, &idx) in &self.labels {
            label_indices.insert(label.clone(), idx);
        }

        // First pass: collect all constant values and build a mapping from instruction index to constant index
        for (idx, instruction) in self.instructions.iter().enumerate() {
            if let Instruction::LDI(_, value) = instruction {
                let const_idx = constants.len();
                constants.push(value.clone());
                const_indices.insert(idx, const_idx);
            }
        }

        // Second pass: resolve instructions
        for (idx, instruction) in self.instructions.iter().enumerate() {
            match instruction {
                Instruction::LD(reg, offset) => {
                    resolved.push(ResolvedInstruction::LD(*reg, *offset));
                },
                Instruction::LDI(reg, _) => {
                    // Get the constant index from the mapping
                    let const_idx = const_indices.get(&idx).unwrap_or(&0);
                    resolved.push(ResolvedInstruction::LDI(*reg, *const_idx));
                },
                Instruction::MOV(dest, src) => {
                    resolved.push(ResolvedInstruction::MOV(*dest, *src));
                },
                Instruction::ADD(dest, src1, src2) => {
                    resolved.push(ResolvedInstruction::ADD(*dest, *src1, *src2));
                },
                Instruction::SUB(dest, src1, src2) => {
                    resolved.push(ResolvedInstruction::SUB(*dest, *src1, *src2));
                },
                Instruction::MUL(dest, src1, src2) => {
                    resolved.push(ResolvedInstruction::MUL(*dest, *src1, *src2));
                },
                Instruction::DIV(dest, src1, src2) => {
                    resolved.push(ResolvedInstruction::DIV(*dest, *src1, *src2));
                },
                Instruction::MOD(dest, src1, src2) => {
                    resolved.push(ResolvedInstruction::MOD(*dest, *src1, *src2));
                },
                Instruction::AND(dest, src1, src2) => {
                    resolved.push(ResolvedInstruction::AND(*dest, *src1, *src2));
                },
                Instruction::OR(dest, src1, src2) => {
                    resolved.push(ResolvedInstruction::OR(*dest, *src1, *src2));
                },
                Instruction::XOR(dest, src1, src2) => {
                    resolved.push(ResolvedInstruction::XOR(*dest, *src1, *src2));
                },
                Instruction::NOT(dest, src) => {
                    resolved.push(ResolvedInstruction::NOT(*dest, *src));
                },
                Instruction::SHL(dest, src, amount) => {
                    resolved.push(ResolvedInstruction::SHL(*dest, *src, *amount));
                },
                Instruction::SHR(dest, src, amount) => {
                    resolved.push(ResolvedInstruction::SHR(*dest, *src, *amount));
                },
                Instruction::JMP(label) => {
                    let target = *label_indices.get(label).unwrap_or(&0);
                    resolved.push(ResolvedInstruction::JMP(target));
                },
                Instruction::JMPEQ(label) => {
                    let target = *label_indices.get(label).unwrap_or(&0);
                    resolved.push(ResolvedInstruction::JMPEQ(target));
                },
                Instruction::JMPNEQ(label) => {
                    let target = *label_indices.get(label).unwrap_or(&0);
                    resolved.push(ResolvedInstruction::JMPNEQ(target));
                },
                Instruction::JMPLT(label) => {
                    let target = *label_indices.get(label).unwrap_or(&0);
                    resolved.push(ResolvedInstruction::JMPLT(target));
                },
                Instruction::JMPGT(label) => {
                    let target = *label_indices.get(label).unwrap_or(&0);
                    resolved.push(ResolvedInstruction::JMPGT(target));
                },
                Instruction::CALL(func_name) => {
                    // Store the function name as a constant and use its index
                    let const_idx = constants.len();
                    constants.push(Value::String(func_name.clone()));
                    resolved.push(ResolvedInstruction::CALL(const_idx));
                },
                Instruction::RET(reg) => {
                    resolved.push(ResolvedInstruction::RET(*reg));
                },
                Instruction::PUSHARG(reg) => {
                    resolved.push(ResolvedInstruction::PUSHARG(*reg));
                },
                Instruction::CMP(reg1, reg2) => {
                    resolved.push(ResolvedInstruction::CMP(*reg1, *reg2));
                },
            }
        }

        self.resolved_instructions = Some(resolved);
        self.constant_values = Some(constants);
    }
}

// Implement Hash manually to avoid issues with HashMap
impl Hash for VMFunction {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.parameters.hash(state);
        self.upvalues.hash(state);
        self.parent.hash(state);
        self.register_count.hash(state);
        self.instructions.hash(state);
        // Skip hashing labels
    }
}

/// Foreign (native) function type
pub type ForeignFunctionPtr = Arc<dyn Fn(ForeignFunctionContext) -> Result<Value, String> + Send + Sync>;

/// Context passed to foreign functions
pub struct ForeignFunctionContext<'a> {
    pub args: &'a [Value],
    pub vm_state: &'a mut VMState,
}

/// Foreign function wrapper
pub struct ForeignFunction {
    pub name: String,
    pub func: ForeignFunctionPtr,
}

impl PartialEq for ForeignFunction {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for ForeignFunction {}

impl Hash for ForeignFunction {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}

impl Clone for ForeignFunction {
    fn clone(&self) -> Self {
        ForeignFunction {
            name: self.name.clone(),
            func: Arc::clone(&self.func)
        }
    }
}

/// Function definition - can be either VM or foreign
#[derive(Clone, Hash)]
pub enum Function {
    VM(VMFunction),
    Foreign(ForeignFunction),
}
