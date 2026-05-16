use super::mpc_engine::MpcEngine;

mod format;
mod lifecycle;
mod local_ops;
mod openings;

pub(crate) use format::ensure_matching_share_data_format;

pub(crate) struct MpcShareRuntime<'engine> {
    engine: &'engine dyn MpcEngine,
}

#[cfg(test)]
mod tests;
