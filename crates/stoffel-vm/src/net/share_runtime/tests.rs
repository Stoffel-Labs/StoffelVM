use super::*;
use crate::net::curve::MpcFieldKind;
use crate::net::mpc_engine::{MpcSessionTopology, ShareAlgebraResult};
use std::sync::{Arc, Mutex};
use stoffel_vm_types::core_types::{ClearShareInput, ClearShareValue, ShareData, ShareType, Value};

#[derive(Default)]
struct PermissiveEngine {
    binary_calls: Mutex<usize>,
    batch_calls: Mutex<usize>,
    interpolate_calls: Mutex<usize>,
}

impl MpcEngine for PermissiveEngine {
    fn protocol_name(&self) -> &'static str {
        "permissive"
    }

    fn topology(&self) -> MpcSessionTopology {
        MpcSessionTopology::try_new(0, 0, 3, 1).expect("test topology should be valid")
    }

    fn is_ready(&self) -> bool {
        true
    }

    fn start(&self) -> crate::net::mpc_engine::MpcEngineResult<()> {
        Ok(())
    }

    fn input_share(
        &self,
        _clear: ClearShareInput,
    ) -> crate::net::mpc_engine::MpcEngineResult<ShareData> {
        Err(crate::net::mpc_engine::MpcEngineError::operation_failed(
            "test_mpc_engine",
            "not implemented",
        ))
    }

    fn open_share(
        &self,
        _ty: ShareType,
        _share_bytes: &[u8],
    ) -> crate::net::mpc_engine::MpcEngineResult<ClearShareValue> {
        Err(crate::net::mpc_engine::MpcEngineError::operation_failed(
            "test_mpc_engine",
            "not implemented",
        ))
    }

    fn batch_open_shares(
        &self,
        _ty: ShareType,
        shares: &[Vec<u8>],
    ) -> crate::net::mpc_engine::MpcEngineResult<Vec<ClearShareValue>> {
        *self.batch_calls.lock().unwrap() += 1;
        Ok(vec![ClearShareValue::Integer(0); shares.len()])
    }

    fn add_share_local(
        &self,
        _ty: ShareType,
        _lhs_bytes: &[u8],
        _rhs_bytes: &[u8],
    ) -> ShareAlgebraResult<Vec<u8>> {
        *self.binary_calls.lock().unwrap() += 1;
        Ok(vec![9])
    }

    fn interpolate_shares_local(
        &self,
        _ty: ShareType,
        _shares: &[Vec<u8>],
    ) -> ShareAlgebraResult<Value> {
        *self.interpolate_calls.lock().unwrap() += 1;
        Ok(Value::I64(0))
    }

    fn field_kind(&self) -> MpcFieldKind {
        MpcFieldKind::Bls12_381Fr
    }
}

fn runtime_for(engine: &PermissiveEngine) -> MpcShareRuntime<'_> {
    MpcShareRuntime::from_configured(Some(engine)).expect("configured engine")
}

fn feldman_share_data() -> ShareData {
    ShareData::Feldman {
        data: vec![2],
        commitments: vec![vec![3]],
    }
}

#[test]
fn binary_ops_reject_mixed_share_data_formats_before_backend_dispatch() {
    let engine = Arc::new(PermissiveEngine::default());
    let runtime = runtime_for(engine.as_ref());

    let err = runtime
        .add_data(
            ShareType::secret_int(64),
            &ShareData::Opaque(vec![1]),
            &feldman_share_data(),
        )
        .expect_err("mixed share data formats should be rejected");

    assert_eq!(
        err.to_string(),
        "Share data format mismatch in add_share_local: left is opaque, right is feldman"
    );
    assert_eq!(*engine.binary_calls.lock().unwrap(), 0);
}

#[test]
fn batch_open_rejects_mixed_share_data_formats_before_backend_dispatch() {
    let engine = Arc::new(PermissiveEngine::default());
    let runtime = runtime_for(engine.as_ref());

    let err = runtime
        .batch_open_share_data(
            ShareType::secret_int(64),
            &[ShareData::Opaque(vec![1]), feldman_share_data()],
        )
        .expect_err("mixed batch share data formats should be rejected");

    assert_eq!(
        err.to_string(),
        "Share data format mismatch in batch_open_shares at index 1: expected opaque, got feldman"
    );
    assert_eq!(*engine.batch_calls.lock().unwrap(), 0);
}

#[test]
fn interpolate_rejects_mixed_share_data_formats_before_backend_dispatch() {
    let engine = Arc::new(PermissiveEngine::default());
    let runtime = runtime_for(engine.as_ref());

    let err = runtime
        .interpolate_share_data_local(
            ShareType::secret_int(64),
            &[ShareData::Opaque(vec![1]), feldman_share_data()],
        )
        .expect_err("mixed interpolation share data formats should be rejected");

    assert_eq!(
        err.to_string(),
        "Share data format mismatch in interpolate_shares_local at index 1: expected opaque, got feldman"
    );
    assert_eq!(*engine.interpolate_calls.lock().unwrap(), 0);
}
