use std::fmt;
use std::num::NonZeroUsize;
use std::time::SystemTime;
use stoffel_vm_types::core_types::{ShareData, ShareType};
use stoffelnet::network_utils::ClientId;

/// Position of a client entry in the VM client-input store.
///
/// The store exposes client IDs in sorted order for VM builtins that address
/// clients by ordinal position. Keeping that position typed prevents accidental
/// reuse as a per-client share index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ClientInputIndex(usize);

impl ClientInputIndex {
    pub const fn new(index: usize) -> Self {
        Self(index)
    }

    pub const fn index(self) -> usize {
        self.0
    }
}

impl fmt::Display for ClientInputIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Number of client entries hydrated from an MPC backend into a VM store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ClientInputHydrationCount(usize);

impl ClientInputHydrationCount {
    pub const ZERO: Self = Self(0);

    pub const fn new(count: usize) -> Self {
        Self(count)
    }

    pub const fn zero() -> Self {
        Self::ZERO
    }

    pub const fn count(self) -> usize {
        self.0
    }

    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl From<usize> for ClientInputHydrationCount {
    fn from(count: usize) -> Self {
        Self::new(count)
    }
}

impl From<ClientInputHydrationCount> for usize {
    fn from(count: ClientInputHydrationCount) -> Self {
        count.count()
    }
}

impl fmt::Display for ClientInputHydrationCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Position of one share within a single client's submitted input vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ClientShareIndex(usize);

impl ClientShareIndex {
    pub const fn new(index: usize) -> Self {
        Self(index)
    }

    pub const fn index(self) -> usize {
        self.0
    }
}

impl fmt::Display for ClientShareIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Number of output shares sent to a client for private reconstruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClientOutputShareCount(NonZeroUsize);

impl ClientOutputShareCount {
    pub const ONE: Self = Self(NonZeroUsize::MIN);

    pub const fn new(count: NonZeroUsize) -> Self {
        Self(count)
    }

    pub fn try_new(count: usize) -> Result<Self, ClientOutputShareCountError> {
        NonZeroUsize::new(count)
            .map(Self)
            .ok_or(ClientOutputShareCountError)
    }

    pub const fn one() -> Self {
        Self::ONE
    }

    pub const fn count(self) -> usize {
        self.0.get()
    }

    pub const fn as_nonzero(self) -> NonZeroUsize {
        self.0
    }
}

impl Default for ClientOutputShareCount {
    fn default() -> Self {
        Self::one()
    }
}

impl TryFrom<usize> for ClientOutputShareCount {
    type Error = ClientOutputShareCountError;

    fn try_from(count: usize) -> Result<Self, Self::Error> {
        Self::try_new(count)
    }
}

impl From<NonZeroUsize> for ClientOutputShareCount {
    fn from(count: NonZeroUsize) -> Self {
        Self::new(count)
    }
}

impl fmt::Display for ClientOutputShareCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientOutputShareCountError;

impl fmt::Display for ClientOutputShareCountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("client output share count must be non-zero")
    }
}

impl std::error::Error for ClientOutputShareCountError {}

/// Share payload stored for a client input.
///
/// The VM can execute against several MPC backends, and not every backend has
/// the same share representation. Keeping the VM-level [`ShareData`] here avoids
/// flattening every client input into opaque bytes during hydration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientShare {
    share_type: Option<ShareType>,
    data: ShareData,
}

impl ClientShare {
    pub fn untyped_bytes(bytes: Vec<u8>) -> Self {
        Self {
            share_type: None,
            data: ShareData::Opaque(bytes),
        }
    }

    pub fn typed(share_type: ShareType, data: ShareData) -> Self {
        Self {
            share_type: Some(share_type),
            data,
        }
    }

    pub fn untyped(data: ShareData) -> Self {
        Self {
            share_type: None,
            data,
        }
    }

    pub fn share_type(&self) -> Option<ShareType> {
        self.share_type
    }

    pub fn data(&self) -> &ShareData {
        &self.data
    }

    pub fn into_data(self) -> ShareData {
        self.data
    }

    pub fn bytes(&self) -> &[u8] {
        self.data.as_bytes()
    }
}

/// A single entry in the client store, representing all shares from one client.
#[derive(Debug, Clone)]
pub struct ClientInputEntry {
    /// The client's ID.
    pub client_id: ClientId,
    /// Shares provided by this client, indexed by input position.
    pub shares: Vec<ClientShare>,
    /// Timestamp when the shares were stored.
    pub timestamp: SystemTime,
}
