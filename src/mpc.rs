use std::future::Future;
use std::pin::Pin;
use crate::vm::RegisterType;

// TODO: figure out a better way to handle this, I imagine that we'll shove the network stack somewhere so this is good to think about

pub trait MPCOperation {
    fn start(&mut self) -> Pin<Box<dyn Future<Output = Result<(), String>>>>;
    fn is_complete(&self) -> bool;
    fn get_result(&self) -> Option<u64>;
}

pub struct MPCAdd {
    operand1: u64,
    operand2: u64,
    result: Option<u64>,
    completed: bool,
}

impl MPCAdd {
    pub fn new(op1: u64, op2: u64) -> Self {
        Self {
            operand1: op1,
            operand2: op2,
            result: None,
            completed: false,
        }
    }
}

impl MPCOperation for MPCAdd {
    fn start(&mut self) -> Pin<Box<dyn Future<Output = Result<(), String>>>> {
        Box::pin(async move {
            // Simulate network delay
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            self.result = Some(self.operand1 + self.operand2);
            self.completed = true;
            Ok(())
        })
    }

    fn is_complete(&self) -> bool {
        self.completed
    }

    fn get_result(&self) -> Option<u64> {
        self.result
    }
}

pub struct MPCOperationFactory;

impl MPCOperationFactory {
    pub fn create_operation(op_type: &str, op1: u64, op2: u64) -> Box<dyn MPCOperation> {
        match op_type {
            "add" => Box::new(MPCAdd::new(op1, op2)),
            // Add more operations as needed
            _ => panic!("Unsupported Multi-Party Computation operation type"),
        }
    }
}
