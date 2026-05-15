mod arithmetic;
mod bitwise;
mod compare;
mod error;
mod share_operands;

pub(crate) use arithmetic::{add, div, modulo, mul, sub};
pub(crate) use bitwise::{bit_and, bit_not, bit_or, bit_xor, shl, shr};
pub(crate) use compare::compare;
pub(crate) use error::ValueOpError;
pub(crate) use share_operands::matching_share_pair;

#[cfg(test)]
mod tests;
