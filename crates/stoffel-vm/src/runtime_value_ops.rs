mod arithmetic;
mod bitwise;
mod compare;
mod error;
mod share_operands;

pub(crate) use arithmetic::{
    add, div, modulo, mul, sub, try_clear_add, try_clear_div, try_clear_modulo, try_clear_mul,
    try_clear_sub,
};
pub(crate) use bitwise::{
    bit_and, bit_not, bit_or, bit_xor, shl, shr, try_clear_bit_and, try_clear_bit_not,
    try_clear_bit_or, try_clear_bit_xor, try_clear_shl, try_clear_shr,
};
pub(crate) use compare::{compare, try_clear_compare};
pub(crate) use error::ValueOpError;
pub(crate) use share_operands::matching_share_pair;

#[cfg(test)]
mod tests;
