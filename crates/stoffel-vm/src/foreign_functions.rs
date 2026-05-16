mod arguments;
mod context;
mod error;
mod function;
mod mpc;
mod services;
mod share_objects;
mod table_memory;

pub use arguments::ForeignArguments;
pub use context::ForeignFunctionContext;
pub use error::{
    ForeignFunctionCallbackError, ForeignFunctionCallbackResult, ForeignFunctionError,
    ForeignFunctionResult,
};
pub use function::{ForeignFunction, ForeignFunctionPtr};

pub(crate) use function::{Function, MpcOnlineBuiltin};

#[cfg(test)]
mod tests;
