use ark_bls12_381::{Fr, G1Projective};
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;

pub type HoneyBadgerShareValueType = Fr;
pub type HoneyBadgerValueType = Fr;
pub type HoneyBadgerShareType = RobustShare<HoneyBadgerShareValueType>;

pub type AvssShareGroupType = G1Projective;
pub type AvssShareValueType = Fr;
pub type AvssValueType = Fr;
pub type AvssShareType = FeldmanShamirShare<AvssShareValueType, AvssShareGroupType>;
