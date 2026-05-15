use super::VMState;
use crate::error::VmResult;
use crate::foreign_functions::{ForeignFunction, Function};
use std::sync::Arc;

impl VMState {
    pub(crate) fn try_insert_function(&mut self, function: Function) -> VmResult<()> {
        self.program.try_insert(function)
    }

    pub(crate) fn has_function(&self, name: &str) -> bool {
        self.program.contains(name)
    }

    pub(crate) fn ensure_function_names_available(
        &self,
        names: &[&str],
        group_name: &str,
    ) -> VmResult<()> {
        self.program.ensure_names_available(names, group_name)
    }

    pub(crate) fn foreign_function(
        &self,
        function_name: &str,
    ) -> VmResult<Option<Arc<ForeignFunction>>> {
        self.program.foreign_function(function_name)
    }
}
