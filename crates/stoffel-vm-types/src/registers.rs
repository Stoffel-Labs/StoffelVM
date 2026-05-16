//! Register-bank layout shared by the compiler-facing types and the VM runtime.

use crate::core_types::Value;
use smallvec::SmallVec;
use std::fmt;

/// Default ABI boundary between clear and secret physical registers.
///
/// The current bytecode format stores register operands as absolute physical
/// indices. By convention, lower indices are clear registers and indices at or
/// above this boundary are secret registers.
pub const DEFAULT_SECRET_REGISTER_START: usize = 16;

/// ABI register used for function return values.
pub const RETURN_REGISTER_INDEX: usize = 0;

/// Minimum frame width required by the VM call/return ABI.
pub const MIN_FRAME_REGISTER_COUNT: usize = RETURN_REGISTER_INDEX + 1;

/// Absolute bytecode register index.
///
/// The VM stores registers in clear and secret banks, but bytecode operands are
/// still absolute frame indices. Use this newtype at register-file boundaries so
/// those operands are not confused with array indices, lengths, or party IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RegisterIndex(usize);

impl RegisterIndex {
    pub const fn new(index: usize) -> Self {
        Self(index)
    }

    pub const fn index(self) -> usize {
        self.0
    }
}

impl fmt::Display for RegisterIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.index().fmt(f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegisterBank {
    Clear,
    Secret,
}

/// Bank-local address for an absolute bytecode register operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RegisterAddress {
    bank: RegisterBank,
    index: usize,
}

impl RegisterAddress {
    pub const fn new(bank: RegisterBank, index: usize) -> Self {
        Self { bank, index }
    }

    pub const fn bank(self) -> RegisterBank {
        self.bank
    }

    pub const fn index(self) -> usize {
        self.index
    }
}

/// Classification for moving a value between physical register banks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegisterMoveKind {
    Copy,
    ClearToSecret,
    SecretToClear,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClearRegisterCopyResult {
    Copied,
    NotClearRegister,
    RegisterOutOfBounds,
    SourcePendingReveal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClearRegisterReadResult {
    Read(Value),
    NotClearRegister,
    RegisterOutOfBounds,
    SourcePendingReveal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretRegisterCopyResult {
    Copied,
    NotSecretRegister,
    RegisterOutOfBounds,
    SourcePendingReveal,
    SourceNotSecretValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RegisterLayout {
    secret_start: usize,
}

impl RegisterLayout {
    pub const DEFAULT: Self = Self {
        secret_start: DEFAULT_SECRET_REGISTER_START,
    };

    pub const fn new(secret_start: usize) -> Self {
        Self { secret_start }
    }

    pub const fn secret_start(self) -> usize {
        self.secret_start
    }

    pub const fn bank(self, register: RegisterIndex) -> RegisterBank {
        if register.index() >= self.secret_start {
            RegisterBank::Secret
        } else {
            RegisterBank::Clear
        }
    }

    pub const fn address(self, register: RegisterIndex) -> RegisterAddress {
        match self.bank(register) {
            RegisterBank::Clear => RegisterAddress::new(RegisterBank::Clear, register.index()),
            RegisterBank::Secret => {
                RegisterAddress::new(RegisterBank::Secret, register.index() - self.secret_start)
            }
        }
    }

    pub const fn is_clear(self, register: RegisterIndex) -> bool {
        matches!(self.bank(register), RegisterBank::Clear)
    }

    pub const fn is_secret(self, register: RegisterIndex) -> bool {
        matches!(self.bank(register), RegisterBank::Secret)
    }

    pub const fn move_kind(self, dest: RegisterIndex, src: RegisterIndex) -> RegisterMoveKind {
        match (self.bank(dest), self.bank(src)) {
            (RegisterBank::Secret, RegisterBank::Clear) => RegisterMoveKind::ClearToSecret,
            (RegisterBank::Clear, RegisterBank::Secret) => RegisterMoveKind::SecretToClear,
            _ => RegisterMoveKind::Copy,
        }
    }
}

impl Default for RegisterLayout {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Clone)]
pub enum RegisterSlot {
    Ready(Value),
    PendingReveal,
}

impl RegisterSlot {
    pub fn ready(value: Value) -> Self {
        Self::Ready(value)
    }

    pub const fn pending_reveal() -> Self {
        Self::PendingReveal
    }

    #[inline]
    pub fn as_value(&self) -> Option<&Value> {
        match self {
            Self::Ready(value) => Some(value),
            Self::PendingReveal => None,
        }
    }

    pub fn as_value_mut(&mut self) -> Option<&mut Value> {
        match self {
            Self::Ready(value) => Some(value),
            Self::PendingReveal => None,
        }
    }

    pub const fn is_pending_reveal(&self) -> bool {
        matches!(self, Self::PendingReveal)
    }
}

impl Default for RegisterSlot {
    fn default() -> Self {
        Self::Ready(Value::Unit)
    }
}

impl From<Value> for RegisterSlot {
    fn from(value: Value) -> Self {
        Self::Ready(value)
    }
}

impl fmt::Debug for RegisterSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready(value) => fmt::Debug::fmt(value, f),
            Self::PendingReveal => f.write_str("<pending reveal>"),
        }
    }
}

impl PartialEq for RegisterSlot {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Ready(left), Self::Ready(right)) => left == right,
            (Self::PendingReveal, Self::PendingReveal) => true,
            _ => false,
        }
    }
}

impl Eq for RegisterSlot {}

#[derive(Clone)]
pub struct RegisterFile {
    layout: RegisterLayout,
    clear: SmallVec<[RegisterSlot; 16]>,
    secret: SmallVec<[RegisterSlot; 16]>,
}

impl RegisterFile {
    pub fn new(layout: RegisterLayout, absolute_len: usize) -> Self {
        let clear_len = absolute_len.min(layout.secret_start());
        let secret_len = absolute_len.saturating_sub(layout.secret_start());
        Self {
            layout,
            clear: default_slots(clear_len),
            secret: default_slots(secret_len),
        }
    }

    pub fn with_default_layout(absolute_len: usize) -> Self {
        Self::new(RegisterLayout::default(), absolute_len)
    }

    pub fn from_absolute_values(layout: RegisterLayout, values: Vec<Value>) -> Self {
        let clear_len = values.len().min(layout.secret_start());
        let mut clear = SmallVec::new();
        let mut secret = SmallVec::new();

        for (index, value) in values.into_iter().enumerate() {
            if index < clear_len {
                clear.push(RegisterSlot::ready(value));
            } else {
                secret.push(RegisterSlot::ready(value));
            }
        }

        Self {
            layout,
            clear,
            secret,
        }
    }

    pub fn layout(&self) -> RegisterLayout {
        self.layout
    }

    pub fn len(&self) -> usize {
        if self.secret.is_empty() {
            self.clear.len()
        } else {
            self.layout.secret_start() + self.secret.len()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.clear.is_empty() && self.secret.is_empty()
    }

    pub fn get_slot(&self, register: RegisterIndex) -> Option<&RegisterSlot> {
        match self.layout.address(register) {
            RegisterAddress {
                bank: RegisterBank::Clear,
                index,
            } => self.clear.get(index),
            RegisterAddress {
                bank: RegisterBank::Secret,
                index,
            } => self.secret.get(index),
        }
    }

    pub fn get_slot_mut(&mut self, register: RegisterIndex) -> Option<&mut RegisterSlot> {
        match self.layout.address(register) {
            RegisterAddress {
                bank: RegisterBank::Clear,
                index,
            } => self.clear.get_mut(index),
            RegisterAddress {
                bank: RegisterBank::Secret,
                index,
            } => self.secret.get_mut(index),
        }
    }

    pub fn contains(&self, register: RegisterIndex) -> bool {
        self.get_slot(register).is_some()
    }

    pub fn get(&self, register: RegisterIndex) -> Option<&Value> {
        self.get_slot(register).and_then(RegisterSlot::as_value)
    }

    pub fn get_mut(&mut self, register: RegisterIndex) -> Option<&mut Value> {
        self.get_slot_mut(register)
            .and_then(RegisterSlot::as_value_mut)
    }

    pub fn replace_value(&mut self, register: RegisterIndex, value: Value) -> Option<RegisterSlot> {
        self.get_slot_mut(register)
            .map(|slot| std::mem::replace(slot, RegisterSlot::ready(value)))
    }

    #[inline]
    pub fn copy_clear_value(
        &mut self,
        dest: RegisterIndex,
        src: RegisterIndex,
    ) -> ClearRegisterCopyResult {
        let dest_index = dest.index();
        let src_index = src.index();

        if dest_index < self.clear.len() && src_index < self.clear.len() {
            return self.copy_clear_bank_value(dest_index, src_index);
        }

        let register_count = self.len();
        if dest_index >= register_count || src_index >= register_count {
            ClearRegisterCopyResult::RegisterOutOfBounds
        } else {
            ClearRegisterCopyResult::NotClearRegister
        }
    }

    #[inline]
    pub fn write_clear_value_from_ref(
        &mut self,
        dest: RegisterIndex,
        value: &Value,
    ) -> ClearRegisterCopyResult {
        let dest_index = dest.index();

        if dest_index < self.clear.len() {
            let value = clone_clear_register_value(value);
            match &mut self.clear[dest_index] {
                RegisterSlot::Ready(dest_value) => *dest_value = value,
                slot @ RegisterSlot::PendingReveal => *slot = RegisterSlot::ready(value),
            }
            return ClearRegisterCopyResult::Copied;
        }

        if dest_index >= self.len() {
            ClearRegisterCopyResult::RegisterOutOfBounds
        } else {
            ClearRegisterCopyResult::NotClearRegister
        }
    }

    #[inline]
    pub fn clone_clear_value(&self, src: RegisterIndex) -> ClearRegisterReadResult {
        let src_index = src.index();

        if src_index < self.clear.len() {
            return match self.clear[src_index].as_value() {
                Some(value) => ClearRegisterReadResult::Read(clone_clear_register_value(value)),
                None => ClearRegisterReadResult::SourcePendingReveal,
            };
        }

        if src_index >= self.len() {
            ClearRegisterReadResult::RegisterOutOfBounds
        } else {
            ClearRegisterReadResult::NotClearRegister
        }
    }

    #[inline]
    pub fn copy_secret_value(
        &mut self,
        dest: RegisterIndex,
        src: RegisterIndex,
    ) -> SecretRegisterCopyResult {
        let dest_index = dest.index();
        let src_index = src.index();
        let register_count = self.len();

        if dest_index >= register_count || src_index >= register_count {
            return SecretRegisterCopyResult::RegisterOutOfBounds;
        }

        let secret_start = self.layout.secret_start();
        if dest_index < secret_start || src_index < secret_start {
            return SecretRegisterCopyResult::NotSecretRegister;
        }

        self.copy_secret_bank_value(dest_index - secret_start, src_index - secret_start)
    }

    #[inline]
    fn copy_secret_bank_value(
        &mut self,
        dest_index: usize,
        src_index: usize,
    ) -> SecretRegisterCopyResult {
        if dest_index == src_index {
            return match self.secret[src_index].as_value() {
                Some(Value::Share(_, _) | Value::Unit) => SecretRegisterCopyResult::Copied,
                Some(_) => SecretRegisterCopyResult::SourceNotSecretValue,
                None => SecretRegisterCopyResult::SourcePendingReveal,
            };
        }

        let (dest_slot, src_slot) = if dest_index < src_index {
            let (left, right) = self.secret.split_at_mut(src_index);
            (&mut left[dest_index], &right[0])
        } else {
            let (left, right) = self.secret.split_at_mut(dest_index);
            (&mut right[0], &left[src_index])
        };

        let Some(src_value) = src_slot.as_value() else {
            return SecretRegisterCopyResult::SourcePendingReveal;
        };
        let Some(value) = clone_secret_register_value(src_value) else {
            return SecretRegisterCopyResult::SourceNotSecretValue;
        };

        match dest_slot {
            RegisterSlot::Ready(dest_value) => *dest_value = value,
            RegisterSlot::PendingReveal => *dest_slot = RegisterSlot::ready(value),
        }

        SecretRegisterCopyResult::Copied
    }

    #[inline]
    fn copy_clear_bank_value(
        &mut self,
        dest_index: usize,
        src_index: usize,
    ) -> ClearRegisterCopyResult {
        if dest_index == src_index {
            return if self.clear[src_index].as_value().is_some() {
                ClearRegisterCopyResult::Copied
            } else {
                ClearRegisterCopyResult::SourcePendingReveal
            };
        }

        let (dest_slot, src_slot) = if dest_index < src_index {
            let (left, right) = self.clear.split_at_mut(src_index);
            (&mut left[dest_index], &right[0])
        } else {
            let (left, right) = self.clear.split_at_mut(dest_index);
            (&mut right[0], &left[src_index])
        };

        let Some(src_value) = src_slot.as_value() else {
            return ClearRegisterCopyResult::SourcePendingReveal;
        };

        let value = clone_clear_register_value(src_value);
        match dest_slot {
            RegisterSlot::Ready(dest_value) => *dest_value = value,
            RegisterSlot::PendingReveal => *dest_slot = RegisterSlot::ready(value),
        }

        ClearRegisterCopyResult::Copied
    }

    pub fn set_pending_reveal(&mut self, register: RegisterIndex) -> Option<RegisterSlot> {
        self.get_slot_mut(register)
            .map(|slot| std::mem::replace(slot, RegisterSlot::pending_reveal()))
    }

    pub fn clear(&mut self) {
        self.clear.clear();
        self.secret.clear();
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Value> {
        self.clear
            .iter_mut()
            .chain(self.secret.iter_mut())
            .filter_map(RegisterSlot::as_value_mut)
    }
}

#[inline]
fn clone_clear_register_value(value: &Value) -> Value {
    match value {
        Value::I64(value) => Value::I64(*value),
        Value::I32(value) => Value::I32(*value),
        Value::I16(value) => Value::I16(*value),
        Value::I8(value) => Value::I8(*value),
        Value::U8(value) => Value::U8(*value),
        Value::U16(value) => Value::U16(*value),
        Value::U32(value) => Value::U32(*value),
        Value::U64(value) => Value::U64(*value),
        Value::Float(value) => Value::Float(*value),
        Value::Bool(value) => Value::Bool(*value),
        Value::Object(value) => Value::Object(*value),
        Value::Array(value) => Value::Array(*value),
        Value::Foreign(value) => Value::Foreign(*value),
        Value::Unit => Value::Unit,
        _ => value.clone(),
    }
}

#[inline]
fn clone_secret_register_value(value: &Value) -> Option<Value> {
    match value {
        Value::Share(ty, data) => Some(Value::Share(*ty, data.clone())),
        Value::Unit => Some(Value::Unit),
        _ => None,
    }
}

fn default_slots(len: usize) -> SmallVec<[RegisterSlot; 16]> {
    let mut slots = SmallVec::new();
    slots.resize(len, RegisterSlot::default());
    slots
}

impl Default for RegisterFile {
    fn default() -> Self {
        Self::with_default_layout(0)
    }
}

impl fmt::Debug for RegisterFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisterFile")
            .field("layout", &self.layout)
            .field("clear", &self.clear)
            .field("secret", &self.secret)
            .finish()
    }
}

impl PartialEq for RegisterFile {
    fn eq(&self, other: &Self) -> bool {
        self.layout == other.layout && self.clear == other.clear && self.secret == other.secret
    }
}

impl Eq for RegisterFile {}

impl From<Vec<Value>> for RegisterFile {
    fn from(values: Vec<Value>) -> Self {
        Self::from_absolute_values(RegisterLayout::default(), values)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn r(index: usize) -> RegisterIndex {
        RegisterIndex::new(index)
    }

    #[test]
    fn register_file_splits_clear_and_secret_banks() {
        let mut registers = RegisterFile::new(RegisterLayout::new(2), 4);

        *registers.get_mut(r(0)).expect("clear register r0") = Value::I64(10);
        *registers.get_mut(r(2)).expect("secret register r2") = Value::I64(20);
        *registers.get_mut(r(3)).expect("secret register r3") = Value::I64(30);

        assert_eq!(registers.layout().bank(r(0)), RegisterBank::Clear);
        assert_eq!(registers.layout().bank(r(2)), RegisterBank::Secret);
        assert_eq!(registers.get(r(0)), Some(&Value::I64(10)));
        assert_eq!(registers.get(r(2)), Some(&Value::I64(20)));
        assert_eq!(registers.get(r(3)), Some(&Value::I64(30)));
        assert_eq!(registers.len(), 4);
    }

    #[test]
    fn pending_reveal_is_explicit_register_state_not_a_vm_value() {
        let mut registers = RegisterFile::new(RegisterLayout::new(2), 3);

        let previous = registers
            .set_pending_reveal(r(0))
            .expect("clear register r0 exists");

        assert_eq!(previous, RegisterSlot::Ready(Value::Unit));
        assert!(registers.contains(r(0)));
        assert_eq!(registers.get(r(0)), None);
        assert!(
            registers
                .get_slot(r(0))
                .is_some_and(RegisterSlot::is_pending_reveal)
        );

        let previous = registers
            .replace_value(r(0), Value::I64(7))
            .expect("clear register r0 exists");
        assert!(previous.is_pending_reveal());
        assert_eq!(registers.get(r(0)), Some(&Value::I64(7)));
    }

    #[test]
    fn register_file_keeps_short_clear_only_frames_compact() {
        let registers = RegisterFile::new(RegisterLayout::default(), 4);

        assert_eq!(registers.len(), 4);
        assert!(registers.get(r(4)).is_none());
    }

    #[test]
    fn register_layout_classifies_bank_crossing_moves() {
        let layout = RegisterLayout::new(2);

        assert_eq!(layout.move_kind(r(0), r(1)), RegisterMoveKind::Copy);
        assert_eq!(
            layout.move_kind(r(2), r(0)),
            RegisterMoveKind::ClearToSecret
        );
        assert_eq!(
            layout.move_kind(r(0), r(2)),
            RegisterMoveKind::SecretToClear
        );
        assert_eq!(layout.move_kind(r(2), r(3)), RegisterMoveKind::Copy);
    }

    #[test]
    fn register_layout_resolves_bank_local_addresses() {
        let layout = RegisterLayout::new(2);

        assert_eq!(
            layout.address(r(1)),
            RegisterAddress::new(RegisterBank::Clear, 1)
        );
        assert_eq!(
            layout.address(r(2)),
            RegisterAddress::new(RegisterBank::Secret, 0)
        );
        assert_eq!(
            layout.address(r(4)),
            RegisterAddress::new(RegisterBank::Secret, 2)
        );
    }

    #[test]
    fn register_file_copies_clear_values_within_clear_bank() {
        let mut registers = RegisterFile::new(RegisterLayout::new(2), 3);
        *registers.get_mut(r(0)).expect("clear register r0") = Value::I64(10);
        *registers.get_mut(r(1)).expect("clear register r1") = Value::I64(20);
        *registers.get_mut(r(2)).expect("secret register r2") = Value::I64(30);

        assert_eq!(
            registers.copy_clear_value(r(0), r(1)),
            ClearRegisterCopyResult::Copied
        );
        assert_eq!(registers.get(r(0)), Some(&Value::I64(20)));
        assert_eq!(
            registers.copy_clear_value(r(1), r(2)),
            ClearRegisterCopyResult::NotClearRegister
        );
        assert_eq!(
            registers.copy_clear_value(r(2), r(1)),
            ClearRegisterCopyResult::NotClearRegister
        );
    }

    #[test]
    fn register_file_clear_copy_reports_pending_source() {
        let mut registers = RegisterFile::new(RegisterLayout::new(2), 2);
        registers
            .set_pending_reveal(r(1))
            .expect("clear register r1 exists");

        assert_eq!(
            registers.copy_clear_value(r(0), r(1)),
            ClearRegisterCopyResult::SourcePendingReveal
        );
    }

    #[test]
    fn register_file_clear_copy_distinguishes_secret_registers_from_out_of_bounds() {
        let mut registers = RegisterFile::new(RegisterLayout::new(2), 4);

        assert_eq!(
            registers.copy_clear_value(r(0), r(2)),
            ClearRegisterCopyResult::NotClearRegister
        );
        assert_eq!(
            registers.copy_clear_value(r(0), r(4)),
            ClearRegisterCopyResult::RegisterOutOfBounds
        );
    }

    #[test]
    fn register_file_writes_clear_value_from_borrowed_source() {
        let mut registers = RegisterFile::new(RegisterLayout::new(2), 4);
        let source = Value::I64(42);

        assert_eq!(
            registers.write_clear_value_from_ref(r(0), &source),
            ClearRegisterCopyResult::Copied
        );
        assert_eq!(registers.get(r(0)), Some(&Value::I64(42)));
        assert_eq!(
            registers.write_clear_value_from_ref(r(2), &source),
            ClearRegisterCopyResult::NotClearRegister
        );
        assert_eq!(
            registers.write_clear_value_from_ref(r(4), &source),
            ClearRegisterCopyResult::RegisterOutOfBounds
        );
    }

    #[test]
    fn register_file_copies_secret_values_within_secret_bank() {
        let mut registers = RegisterFile::new(RegisterLayout::new(2), 4);
        let share = Value::Share(
            crate::core_types::ShareType::secret_int(64),
            crate::core_types::ShareData::Opaque(vec![7]),
        );
        *registers.get_mut(r(2)).expect("secret register r2") = share.clone();

        assert_eq!(
            registers.copy_secret_value(r(3), r(2)),
            SecretRegisterCopyResult::Copied
        );
        assert_eq!(registers.get(r(3)), Some(&share));
        assert_eq!(
            registers.copy_secret_value(r(1), r(2)),
            SecretRegisterCopyResult::NotSecretRegister
        );
        assert_eq!(
            registers.copy_secret_value(r(3), r(4)),
            SecretRegisterCopyResult::RegisterOutOfBounds
        );
    }

    #[test]
    fn register_file_secret_copy_reports_pending_and_clear_sources() {
        let mut registers = RegisterFile::new(RegisterLayout::new(2), 4);
        *registers.get_mut(r(2)).expect("secret register r2") = Value::I64(7);
        registers
            .set_pending_reveal(r(3))
            .expect("secret register r3 exists");

        assert_eq!(
            registers.copy_secret_value(r(3), r(2)),
            SecretRegisterCopyResult::SourceNotSecretValue
        );
        assert_eq!(
            registers.copy_secret_value(r(2), r(3)),
            SecretRegisterCopyResult::SourcePendingReveal
        );
    }

    #[test]
    fn register_file_equality_includes_bank_layout() {
        let values = vec![Value::I64(1), Value::I64(2), Value::I64(3)];

        let clear_only =
            RegisterFile::from_absolute_values(RegisterLayout::new(16), values.clone());
        let split_banks = RegisterFile::from_absolute_values(RegisterLayout::new(2), values);

        assert_ne!(clear_only, split_banks);
        assert_eq!(
            clear_only,
            RegisterFile::from_absolute_values(
                RegisterLayout::new(16),
                vec![Value::I64(1), Value::I64(2), Value::I64(3)]
            )
        );
    }
}
