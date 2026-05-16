use super::{
    ForeignFunctionCallbackResult, ForeignFunctionContext, ForeignFunctionError,
    ForeignFunctionResult,
};
use std::sync::Arc;
use stoffel_vm_types::core_types::Value;
use stoffel_vm_types::functions::VMFunction;

/// Foreign native function pointer stored by the VM.
pub type ForeignFunctionPtr =
    Arc<dyn Fn(ForeignFunctionContext) -> ForeignFunctionCallbackResult<Value> + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MpcOnlineBuiltin {
    FromClear,
    FromClearInt,
    FromClearFixed,
    Mul,
    Open,
    BatchOpen,
    SendToClient,
    OpenExp,
    Random,
    OpenField,
    OpenExpCustom,
    RbcBroadcast,
    RbcReceive,
    RbcReceiveAny,
    AbaPropose,
    AbaResult,
    AbaProposeAndWait,
}

impl MpcOnlineBuiltin {
    pub(crate) const fn function_name(self) -> &'static str {
        match self {
            Self::FromClear => "Share.from_clear",
            Self::FromClearInt => "Share.from_clear_int",
            Self::FromClearFixed => "Share.from_clear_fixed",
            Self::Mul => "Share.mul",
            Self::Open => "Share.open",
            Self::BatchOpen => "Share.batch_open",
            Self::SendToClient => "Share.send_to_client",
            Self::OpenExp => "Share.open_exp",
            Self::Random => "Share.random",
            Self::OpenField => "Share.open_field",
            Self::OpenExpCustom => "Share.open_exp_custom",
            Self::RbcBroadcast => "Rbc.broadcast",
            Self::RbcReceive => "Rbc.receive",
            Self::RbcReceiveAny => "Rbc.receive_any",
            Self::AbaPropose => "Aba.propose",
            Self::AbaResult => "Aba.result",
            Self::AbaProposeAndWait => "Aba.propose_and_wait",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ForeignFunctionKind {
    Generic,
    MpcOnlineBuiltin(MpcOnlineBuiltin),
}

/// Foreign function wrapper.
///
/// This associates a stable VM-visible name with a Rust callback so foreign
/// functions can be stored in the same program registry as bytecode functions.
pub struct ForeignFunction {
    name: String,
    func: ForeignFunctionPtr,
    kind: ForeignFunctionKind,
}

impl ForeignFunction {
    pub fn new(name: impl Into<String>, func: ForeignFunctionPtr) -> Self {
        Self {
            name: name.into(),
            func,
            kind: ForeignFunctionKind::Generic,
        }
    }

    pub(crate) fn mpc_online_builtin(builtin: MpcOnlineBuiltin, func: ForeignFunctionPtr) -> Self {
        Self {
            name: builtin.function_name().to_owned(),
            func,
            kind: ForeignFunctionKind::MpcOnlineBuiltin(builtin),
        }
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) const fn mpc_online_builtin_kind(&self) -> Option<MpcOnlineBuiltin> {
        match self.kind {
            ForeignFunctionKind::Generic => None,
            ForeignFunctionKind::MpcOnlineBuiltin(builtin) => Some(builtin),
        }
    }

    pub fn call(&self, context: ForeignFunctionContext<'_>) -> ForeignFunctionResult<Value> {
        (self.func)(context).map_err(|source| ForeignFunctionError::CallbackFailed {
            function: self.name.clone(),
            source,
        })
    }
}

/// Registered function payload.
///
/// VM and foreign functions share registration, lookup, and call plumbing, but
/// keep distinct payloads so bytecode compilation and native callbacks evolve
/// independently. This is a registration transfer type; callable sharing is
/// handled explicitly by `Program`.
pub(crate) enum Function {
    VM(Box<VMFunction>),
    Foreign(ForeignFunction),
}

impl Function {
    pub(crate) fn vm(function: VMFunction) -> Self {
        Self::VM(Box::new(function))
    }

    pub(crate) fn foreign(function: ForeignFunction) -> Self {
        Self::Foreign(function)
    }

    pub fn name(&self) -> &str {
        match self {
            Function::VM(function) => function.name(),
            Function::Foreign(function) => function.name(),
        }
    }
}
