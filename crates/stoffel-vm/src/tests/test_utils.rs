//! Shared test utilities for integration tests.

use crate::core_vm::VirtualMachine;
use std::sync::{Once, OnceLock};
use stoffel_vm_types::core_types::{ArrayRef, TableMemory, TableRef, Value};
use tokio::sync::{Mutex, MutexGuard};

static CRYPTO_INIT: Once = Once::new();
#[allow(dead_code)]
static TRACING_INIT: Once = Once::new();
#[allow(dead_code)]
static HB_ITEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// Initialize the rustls crypto provider (idempotent, safe to call from multiple tests).
pub(crate) fn init_crypto_provider() {
    CRYPTO_INIT.call_once(|| {
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
    });
}

/// Set up a tracing subscriber for test output (idempotent, safe to call from multiple tests).
#[allow(dead_code)]
pub(crate) fn setup_test_tracing() {
    use tracing_subscriber::{EnvFilter, FmtSubscriber};

    TRACING_INIT.call_once(|| {
        let subscriber = FmtSubscriber::builder()
            .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
            .with_test_writer()
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    });
}

/// Serialize HoneyBadger integration tests that share process-global networking state.
#[allow(dead_code)]
pub(crate) async fn acquire_hb_itest_lock() -> MutexGuard<'static, ()> {
    HB_ITEST_LOCK.get_or_init(|| Mutex::new(())).lock().await
}

#[allow(dead_code)]
pub(crate) fn read_table_array(
    memory: &mut dyn TableMemory,
    array_id: usize,
) -> Result<Vec<Value>, String> {
    let array_ref = ArrayRef::new(array_id);
    let len = memory.read_array_ref_len(array_ref)?;
    (0..len)
        .map(|index| {
            let index_value = table_index(array_id, index)?;
            memory
                .read_table_field(TableRef::from(array_ref), &index_value)
                .map_err(|e| format!("Failed to read array {} element {}: {}", array_id, index, e))?
                .ok_or_else(|| format!("Array {} missing element {}", array_id, index))
        })
        .collect()
}

#[allow(dead_code)]
pub(crate) fn read_table_byte_array(
    memory: &mut dyn TableMemory,
    array_id: usize,
) -> Result<Vec<u8>, String> {
    read_table_array(memory, array_id)?
        .into_iter()
        .enumerate()
        .map(|(index, value)| match value {
            Value::U8(byte) => Ok(byte),
            other => Err(format!(
                "Array {} element {} is {:?}, expected uint8",
                array_id, index, other
            )),
        })
        .collect()
}

#[allow(dead_code)]
pub(crate) fn read_table_number(
    memory: &mut dyn TableMemory,
    array_id: usize,
    index: usize,
) -> Result<f64, String> {
    let index_value = table_index(array_id, index)?;
    let array_ref = ArrayRef::new(array_id);
    match memory
        .read_table_field(TableRef::from(array_ref), &index_value)
        .map_err(|e| format!("Failed to read array {} element {}: {}", array_id, index, e))?
        .ok_or_else(|| format!("Array {} missing element {}", array_id, index))?
    {
        Value::I64(value) => Ok(value as f64),
        Value::Float(value) => Ok(value.0),
        other => Err(format!(
            "Array {} element {} is {:?}, expected numeric value",
            array_id, index, other
        )),
    }
}

#[allow(dead_code)]
pub(crate) fn read_vm_table_array(
    vm: &mut VirtualMachine,
    array_id: usize,
) -> Result<Vec<Value>, String> {
    let array_ref = ArrayRef::new(array_id);
    let len = vm
        .read_array_len(array_ref)
        .map_err(|e| format!("Failed to read array {array_id} length: {e}"))?;
    let table_ref = TableRef::from(array_ref);
    (0..len)
        .map(|index| {
            let index_value = table_index(array_id, index)?;
            vm.read_table_field(table_ref, &index_value)
                .map_err(|e| format!("Failed to read array {} element {}: {}", array_id, index, e))?
                .ok_or_else(|| format!("Array {} missing element {}", array_id, index))
        })
        .collect()
}

#[allow(dead_code)]
pub(crate) fn read_vm_table_byte_array(
    vm: &mut VirtualMachine,
    array_id: usize,
) -> Result<Vec<u8>, String> {
    read_vm_table_array(vm, array_id)?
        .into_iter()
        .enumerate()
        .map(|(index, value)| match value {
            Value::U8(byte) => Ok(byte),
            other => Err(format!(
                "Array {} element {} is {:?}, expected uint8",
                array_id, index, other
            )),
        })
        .collect()
}

#[allow(dead_code)]
pub(crate) fn read_vm_table_number(
    vm: &mut VirtualMachine,
    array_id: usize,
    index: usize,
) -> Result<f64, String> {
    let index_value = table_index(array_id, index)?;
    match vm
        .read_table_field(TableRef::array(array_id), &index_value)
        .map_err(|e| format!("Failed to read array {} element {}: {}", array_id, index, e))?
        .ok_or_else(|| format!("Array {} missing element {}", array_id, index))?
    {
        Value::I64(value) => Ok(value as f64),
        Value::Float(value) => Ok(value.0),
        other => Err(format!(
            "Array {} element {} is {:?}, expected numeric value",
            array_id, index, other
        )),
    }
}

fn table_index(array_id: usize, index: usize) -> Result<Value, String> {
    let index = i64::try_from(index).map_err(|_| {
        format!(
            "Array {} index {} exceeds VM integer range",
            array_id, index
        )
    })?;
    Ok(Value::I64(index))
}
