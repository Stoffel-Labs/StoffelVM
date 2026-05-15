use super::ForeignFunctionCallbackResult;
use crate::value_conversions::{value_to_u64, value_to_usize};
use stoffel_vm_types::core_types::{ArrayRef, ObjectRef, Value};

/// Named argument view for a VM foreign-function call.
///
/// Keeping arity and type checks behind this small facade prevents builtins
/// and user-provided native functions from open-coding slightly different
/// validation logic at every call site.
pub struct ForeignArguments<'a> {
    function: &'static str,
    args: &'a [Value],
}

impl<'a> ForeignArguments<'a> {
    pub(crate) fn new(function: &'static str, args: &'a [Value]) -> Self {
        Self { function, args }
    }

    /// Require at least `min` arguments.
    ///
    /// `expectation` is the user-facing suffix after "`<function> expects`",
    /// for example `"2 arguments: left, right"`.
    pub fn require_min(
        &self,
        min: usize,
        expectation: &'static str,
    ) -> ForeignFunctionCallbackResult<()> {
        if self.args.len() >= min {
            Ok(())
        } else {
            Err(format!("{} expects {}", self.function, expectation).into())
        }
    }

    /// Require exactly `expected` arguments.
    ///
    /// `expectation` is the user-facing suffix after "`<function> expects`",
    /// for example `"1 argument: value"`.
    pub fn require_exact(
        &self,
        expected: usize,
        expectation: &'static str,
    ) -> ForeignFunctionCallbackResult<()> {
        if self.args.len() == expected {
            Ok(())
        } else {
            Err(format!("{} expects {}", self.function, expectation).into())
        }
    }

    /// Get an argument by index or return a callback error that names the function.
    pub fn get(&self, index: usize) -> ForeignFunctionCallbackResult<&'a Value> {
        self.args
            .get(index)
            .ok_or_else(|| format!("{} missing argument {}", self.function, index).into())
    }

    /// Clone an argument by index.
    ///
    /// This is useful when the foreign function also needs mutable access to
    /// VM services after validating arguments.
    pub fn cloned(&self, index: usize) -> ForeignFunctionCallbackResult<Value> {
        self.get(index).cloned()
    }

    /// Borrow an argument as a string slice.
    pub fn string(
        &self,
        index: usize,
        argument_name: &'static str,
    ) -> ForeignFunctionCallbackResult<&'a str> {
        match self.get(index)? {
            Value::String(value) => Ok(value),
            _ => Err(format!("{argument_name} must be a string").into()),
        }
    }

    /// Clone an argument as an owned string.
    pub fn cloned_string(
        &self,
        index: usize,
        argument_name: &'static str,
    ) -> ForeignFunctionCallbackResult<String> {
        Ok(self.string(index, argument_name)?.to_owned())
    }

    /// Read an argument as a VM object reference.
    pub fn object_ref(
        &self,
        index: usize,
        argument_name: &'static str,
    ) -> ForeignFunctionCallbackResult<ObjectRef> {
        ObjectRef::try_from(self.get(index)?)
            .map_err(|_| format!("{argument_name} must be an object").into())
    }

    /// Read an argument as a VM array reference.
    pub fn array_ref(
        &self,
        index: usize,
        argument_name: &'static str,
    ) -> ForeignFunctionCallbackResult<ArrayRef> {
        ArrayRef::try_from(self.get(index)?)
            .map_err(|_| format!("{argument_name} must be an array").into())
    }

    /// Read an argument as a VM array id.
    pub fn array_id(
        &self,
        index: usize,
        argument_name: &'static str,
    ) -> ForeignFunctionCallbackResult<usize> {
        Ok(self.array_ref(index, argument_name)?.id())
    }

    /// Convert an integer-like VM value into `usize`.
    pub fn usize(
        &self,
        index: usize,
        argument_name: &'static str,
    ) -> ForeignFunctionCallbackResult<usize> {
        Ok(value_to_usize(self.get(index)?, argument_name)?)
    }

    /// Convert an integer-like VM value into `u64`.
    pub fn u64(
        &self,
        index: usize,
        argument_name: &'static str,
    ) -> ForeignFunctionCallbackResult<u64> {
        Ok(value_to_u64(self.get(index)?, argument_name)?)
    }

    /// Read an argument as a boolean.
    pub fn bool(
        &self,
        index: usize,
        argument_name: &'static str,
    ) -> ForeignFunctionCallbackResult<bool> {
        match self.get(index)? {
            Value::Bool(value) => Ok(*value),
            _ => Err(format!("{argument_name} must be a boolean").into()),
        }
    }

    /// Borrow all arguments from `index` onward.
    pub fn tail_from(&self, index: usize) -> ForeignFunctionCallbackResult<&'a [Value]> {
        self.args.get(index..).ok_or_else(|| {
            format!("{} missing arguments starting at {}", self.function, index).into()
        })
    }
}
