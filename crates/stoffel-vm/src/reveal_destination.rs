//! VM destinations for queued reveal operations.
//!
//! Reveal batching lives next to the MPC engine integration, but the destination
//! itself is VM execution state: it identifies which activation frame and
//! register should receive an opened value.

use crate::runtime_instruction::RuntimeRegister;

/// Call-frame depth used to scope pending reveal operations.
///
/// A reveal queued by one activation frame must not be flushed into another
/// frame's registers. Keeping the depth typed makes that boundary explicit
/// instead of passing unrelated `usize` values through the MPC runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct FrameDepth(usize);

impl FrameDepth {
    pub(crate) const fn new(depth: usize) -> Self {
        Self(depth)
    }

    pub(crate) const fn depth(self) -> usize {
        self.0
    }
}

/// Destination register for a pending reveal, scoped to the activation frame
/// that queued it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct RevealDestination {
    frame_depth: FrameDepth,
    register: RuntimeRegister,
}

impl RevealDestination {
    pub(crate) const fn new(frame_depth: FrameDepth, register: RuntimeRegister) -> Self {
        Self {
            frame_depth,
            register,
        }
    }

    pub(crate) const fn frame_depth(self) -> FrameDepth {
        self.frame_depth
    }

    pub(crate) const fn register(self) -> RuntimeRegister {
        self.register
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reveal_destination_carries_a_validated_runtime_register() {
        let register = RuntimeRegister::try_new(2, 3).expect("register is in frame");
        let destination = RevealDestination::new(FrameDepth::new(1), register);

        assert_eq!(destination.frame_depth(), FrameDepth::new(1));
        assert_eq!(destination.register(), register);
        assert_eq!(destination.register().index(), 2);
    }
}
