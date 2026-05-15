use super::*;
use crate::core_vm::VirtualMachine;
use crate::mpc_values::byte_arrays::{create_byte_array, extract_byte_array};
use crate::net::curve::MpcFieldKind;
use crate::net::mpc_engine::{
    MpcCapabilities, MpcEngine, MpcEngineError, MpcEngineOpenInExponent, MpcEngineResult,
    MpcExponentGroup, MpcSessionTopology,
};
use crate::VirtualMachineErrorKind;
use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex};
use stoffel_vm_types::core_types::{
    ArrayRef, ClearShareInput, ClearShareValue, ObjectRef, ObjectStore, ShareData, ShareType,
    TableMemory, TableRef, Value,
};
use stoffel_vm_types::functions::VMFunction;
use stoffel_vm_types::instructions::Instruction;

fn callback_runtime_kind(error: &crate::VirtualMachineError) -> Option<VirtualMachineErrorKind> {
    let mut source = error.source();
    while let Some(error) = source {
        if let Some(callback_error) =
            error.downcast_ref::<crate::foreign_functions::ForeignFunctionCallbackError>()
        {
            return callback_error.runtime_kind();
        }
        if let Some(crate::foreign_functions::ForeignFunctionError::CallbackFailed {
            source, ..
        }) = error.downcast_ref::<crate::foreign_functions::ForeignFunctionError>()
        {
            return source.runtime_kind();
        }
        source = error.source();
    }

    None
}

struct NoOpenExpEngine;

impl MpcEngine for NoOpenExpEngine {
    fn protocol_name(&self) -> &'static str {
        "no-open-exp"
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
    fn shutdown(&self) {}
    fn field_kind(&self) -> MpcFieldKind {
        MpcFieldKind::Bls12_381Fr
    }
}

struct RecordingOpenExpEngine {
    group_seen: Arc<Mutex<Option<MpcExponentGroup>>>,
}

impl MpcEngine for RecordingOpenExpEngine {
    fn protocol_name(&self) -> &'static str {
        "recording-open-exp"
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
    fn capabilities(&self) -> MpcCapabilities {
        MpcCapabilities::OPEN_IN_EXP
    }
    fn as_open_in_exp(&self) -> Option<&dyn MpcEngineOpenInExponent> {
        Some(self)
    }
    fn shutdown(&self) {}
    fn field_kind(&self) -> MpcFieldKind {
        MpcFieldKind::Bls12_381Fr
    }
}

impl MpcEngineOpenInExponent for RecordingOpenExpEngine {
    fn open_share_in_exp(
        &self,
        _ty: ShareType,
        _share_bytes: &[u8],
        _generator_bytes: &[u8],
    ) -> MpcEngineResult<Vec<u8>> {
        Err(MpcEngineError::operation_failed(
            "open_share_in_exp",
            "legacy exponent-open path should not be used",
        ))
    }

    fn open_share_in_exp_group(
        &self,
        group: MpcExponentGroup,
        _ty: ShareType,
        share_bytes: &[u8],
        generator_bytes: &[u8],
    ) -> MpcEngineResult<Vec<u8>> {
        if share_bytes != [1, 2, 3, 4] {
            return Err(MpcEngineError::operation_failed(
                "open_share_in_exp_group",
                format!("unexpected share bytes: {:?}", share_bytes),
            ));
        }
        if generator_bytes.is_empty() {
            return Err(MpcEngineError::operation_failed(
                "open_share_in_exp_group",
                "generator bytes should not be empty",
            ));
        }

        *self
            .group_seen
            .lock()
            .expect("group recording lock should not be poisoned") = Some(group);

        Ok(vec![5, 6, 7, 8])
    }
}

#[test]
fn try_register_mpc_builtins_rejects_duplicate_registration() {
    let mut vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_builtins(false)
        .build();

    try_register_mpc_builtins(&mut vm).expect("first MPC builtin registration should succeed");
    let err = try_register_mpc_builtins(&mut vm)
        .expect_err("second MPC builtin registration must be rejected");
    assert_eq!(err.kind(), VirtualMachineErrorKind::Registration);
    let err = err.to_string();

    assert!(
        err.contains("Share.from_clear") && err.contains("already registered"),
        "unexpected error: {err}"
    );
    assert!(vm.has_function("Share.open"));
}

#[test]
fn mpc_info_builtins_expose_backend_identity_and_capabilities() {
    let group_seen = Arc::new(Mutex::new(None));
    let mut vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_engine(Arc::new(RecordingOpenExpEngine {
            group_seen: Arc::clone(&group_seen),
        }))
        .build();

    assert_eq!(
        vm.execute_with_args("Mpc.protocol_name", &[]).unwrap(),
        Value::String("recording-open-exp".to_string())
    );
    assert_eq!(
        vm.execute_with_args("Mpc.curve", &[]).unwrap(),
        Value::String("bls12-381".to_string())
    );
    assert_eq!(
        vm.execute_with_args("Mpc.field", &[]).unwrap(),
        Value::String("bls12-381-fr".to_string())
    );
    assert_eq!(
        vm.execute_with_args(
            "Mpc.has_capability",
            &[Value::String("open_in_exp".to_string())],
        )
        .unwrap(),
        Value::Bool(true)
    );
    assert_eq!(
        vm.execute_with_args(
            "Mpc.has_capability",
            &[Value::String("multiplication".to_string())],
        )
        .unwrap(),
        Value::Bool(false)
    );

    let capabilities = vm.execute_with_args("Mpc.capabilities", &[]).unwrap();
    let Value::Array(capabilities_ref) = capabilities else {
        panic!("Mpc.capabilities should return an array");
    };
    assert_eq!(vm.read_array_len(capabilities_ref).unwrap(), 1);
    assert_eq!(
        vm.read_table_field(TableRef::from(capabilities_ref), &Value::I64(0),)
            .unwrap(),
        Some(Value::String("open-in-exponent".to_string()))
    );
}

#[test]
fn mpc_has_capability_rejects_unknown_capability_names() {
    let mut vm = VirtualMachine::builder()
        .with_standard_library(false)
        .with_mpc_engine(Arc::new(NoOpenExpEngine))
        .build();

    let err = vm
        .execute_with_args(
            "Mpc.has_capability",
            &[Value::String("not-a-capability".to_string())],
        )
        .expect_err("unknown capability names should be rejected");

    assert_eq!(err.kind(), VirtualMachineErrorKind::ForeignFunction);
    assert!(
        err.to_string()
            .contains("Unsupported MPC capability: not-a-capability"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_share_object_creation() {
    let mut store = ObjectStore::new();
    let share_type = ShareType::default_secret_int();
    let data = vec![1, 2, 3, 4];
    let party_id = 0;

    let share_ref = share_object::create_share_object_ref(
        &mut store,
        share_type,
        ShareData::Opaque(data.clone()),
        party_id,
    )
    .expect("share object creation should succeed");

    // Verify we can extract the share data
    let result = share_object::extract_share_data_ref(&mut store, share_ref);
    assert!(result.is_ok());
    let (ty, extracted_data) = result.unwrap();
    assert_eq!(ty, share_type);
    assert_eq!(extracted_data, ShareData::Opaque(data));
}

#[test]
fn share_object_type_metadata_rejects_invalid_integer_conversions() {
    let mut store = ObjectStore::new();
    let object_ref = store
        .create_object_ref()
        .expect("create malformed share object");
    let table_ref = TableRef::from(object_ref);
    store
        .set_table_field(
            table_ref,
            Value::String(share_fields::TYPE.to_string()),
            Value::String(share_fields::TYPE_VALUE.to_string()),
        )
        .expect("set share type tag");
    store
        .set_table_field(
            table_ref,
            Value::String(share_fields::SHARE_TYPE.to_string()),
            Value::String(share_fields::SECRET_INT.to_string()),
        )
        .expect("set share type field");
    store
        .set_table_field(
            table_ref,
            Value::String(share_fields::BIT_LENGTH.to_string()),
            Value::I64(-1),
        )
        .expect("set invalid bit length field");
    store
        .set_table_field(
            table_ref,
            Value::String(share_fields::DATA.to_string()),
            Value::Share(ShareType::default_secret_int(), ShareData::Opaque(vec![])),
        )
        .expect("set share data field");

    let object = Value::from(object_ref);
    let err = share_object::get_share_type(&mut store, &object)
        .expect_err("negative bit length must be rejected");
    let err = err.to_string();

    assert!(
        err.contains("bit_length") && err.contains("non-negative integer"),
        "unexpected error: {err}"
    );
}

#[test]
fn share_object_extraction_rejects_metadata_type_mismatch() {
    let mut store = ObjectStore::new();
    let share_ref = share_object::create_share_object_ref(
        &mut store,
        ShareType::secret_int(64),
        ShareData::Opaque(vec![1, 2, 3, 4]),
        0,
    )
    .expect("share object creation should succeed");
    let object = Value::from(share_ref);

    store
        .set_table_field(
            TableRef::from(share_ref),
            Value::String(share_fields::SHARE_TYPE.to_string()),
            Value::String(share_fields::SECRET_FIXED_POINT.to_string()),
        )
        .expect("set conflicting share type");
    store
        .set_table_field(
            TableRef::from(share_ref),
            Value::String(share_fields::PRECISION_K.to_string()),
            Value::I64(64),
        )
        .expect("set precision k");
    store
        .set_table_field(
            TableRef::from(share_ref),
            Value::String(share_fields::PRECISION_F.to_string()),
            Value::I64(16),
        )
        .expect("set precision f");

    let err = share_object::extract_share_data(&mut store, &object)
        .expect_err("metadata must agree with the embedded share data type");
    let err = err.to_string();

    assert!(
        err.contains("metadata type") && err.contains("__data type"),
        "unexpected error: {err}"
    );
}

#[test]
fn share_mul_field_preserves_feldman_share_data() {
    use ark_bls12_381::{Fr, G1Projective};
    use ark_ec::PrimeGroup;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;

    let mut vm = VirtualMachine::builder().with_mpc_builtins(false).build();
    register_mpc_builtins(&mut vm);
    vm.set_mpc_engine(Arc::new(NoOpenExpEngine));

    let share_value = Fr::from(7u64);
    let commitment = G1Projective::generator() * share_value;
    let share =
        FeldmanShamirShare::new(share_value, 1, 0, vec![commitment]).expect("create Feldman share");
    let mut share_bytes = Vec::new();
    share
        .serialize_compressed(&mut share_bytes)
        .expect("serialize Feldman share");

    let share_value = vm
        .create_share_object(
            ShareType::secret_int(64),
            ShareData::Feldman {
                data: share_bytes,
                commitments: Vec::new(),
            },
            0,
        )
        .expect("share object creation should succeed");

    let mut field_bytes = Vec::new();
    Fr::from(3u64)
        .serialize_compressed(&mut field_bytes)
        .expect("serialize field scalar");
    let field_array = vm
        .create_byte_array(&field_bytes)
        .expect("field byte array");

    let fn_call = VMFunction::new(
        "test_share_mul_field".to_string(),
        vec![],
        Vec::new(),
        None,
        4,
        vec![
            Instruction::LDI(0, share_value),
            Instruction::LDI(1, field_array),
            Instruction::PUSHARG(0),
            Instruction::PUSHARG(1),
            Instruction::CALL("Share.mul_field".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );
    vm.register_function(fn_call);

    let result = vm
        .execute("test_share_mul_field")
        .expect("Share.mul_field should execute");
    let (_ty, result_data) = vm
        .read_share_object(&result)
        .expect("result should be a valid Share object");
    let commitments = result_data
        .commitments()
        .expect("Feldman data should remain Feldman after Share.mul_field");
    assert_eq!(commitments.len(), 1);

    let decoded =
        FeldmanShamirShare::<Fr, G1Projective>::deserialize_compressed(result_data.as_bytes())
            .expect("decode multiplied Feldman share");
    assert_eq!(decoded.feldmanshare.share[0], Fr::from(21u64));
    assert_eq!(
        decoded.commitments[0],
        G1Projective::generator() * Fr::from(21u64)
    );
}

#[test]
fn share_from_clear_rejects_unsigned_values_outside_vm_integer_range() {
    let mut vm = VirtualMachine::builder().with_mpc_builtins(false).build();
    register_mpc_builtins(&mut vm);
    vm.set_mpc_engine(Arc::new(NoOpenExpEngine));

    let err = vm
        .execute_with_args(
            "Share.from_clear",
            &[Value::U64(u64::try_from(i64::MAX).unwrap() + 1)],
        )
        .expect_err("oversized unsigned clear value must not truncate to i64");
    assert_eq!(err.kind(), VirtualMachineErrorKind::ForeignFunction);
    assert_eq!(
        callback_runtime_kind(&err),
        Some(VirtualMachineErrorKind::Mpc)
    );
    let err = err.to_string();

    assert!(
        err.contains("clear integer") && err.contains("exceeds i64 range"),
        "unexpected error: {err}"
    );
}

#[test]
fn share_mul_reports_missing_multiplication_capability_through_vm_runtime() {
    let mut vm = VirtualMachine::builder().with_mpc_builtins(false).build();
    register_mpc_builtins(&mut vm);
    vm.set_mpc_engine(Arc::new(NoOpenExpEngine));
    let ty = ShareType::default_secret_int();

    let err = vm
        .execute_with_args(
            "Share.mul",
            &[
                Value::Share(ty, ShareData::Opaque(vec![1])),
                Value::Share(ty, ShareData::Opaque(vec![2])),
            ],
        )
        .expect_err("Share.mul should require the multiplication capability");

    assert_eq!(err.kind(), VirtualMachineErrorKind::ForeignFunction);
    assert_eq!(
        callback_runtime_kind(&err),
        Some(VirtualMachineErrorKind::Mpc)
    );
    let err = err.to_string();
    assert!(
        err.contains("does not support multiplication"),
        "unexpected error: {err}"
    );
}

#[test]
fn share_random_reports_missing_randomness_capability_through_vm_runtime() {
    let mut vm = VirtualMachine::builder().with_mpc_builtins(false).build();
    register_mpc_builtins(&mut vm);
    vm.set_mpc_engine(Arc::new(NoOpenExpEngine));

    let err = vm
        .execute_with_args("Share.random", &[])
        .expect_err("Share.random should require the randomness capability");

    assert_eq!(err.kind(), VirtualMachineErrorKind::ForeignFunction);
    assert_eq!(
        callback_runtime_kind(&err),
        Some(VirtualMachineErrorKind::Mpc)
    );
    let err = err.to_string();
    assert!(
        err.contains("does not support jointly-random share generation"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_is_share_object() {
    let mut store = ObjectStore::new();
    let share_type = ShareType::default_secret_int();
    let data = vec![1, 2, 3, 4];

    let share_ref =
        share_object::create_share_object_ref(&mut store, share_type, ShareData::Opaque(data), 0)
            .expect("share object creation should succeed");
    let non_share_ref = store.create_object_ref().expect("create non-share object");

    assert!(share_object::is_share_object(
        &mut store,
        &Value::from(share_ref)
    ));
    assert!(!share_object::is_share_object(
        &mut store,
        &Value::from(non_share_ref)
    ));
    assert!(share_object::is_share_object(
        &mut store,
        &Value::Share(share_type, ShareData::Opaque(vec![]))
    ));
    assert!(!share_object::is_share_object(&mut store, &Value::I64(42)));
}

#[test]
fn byte_array_helpers_work_through_table_memory_trait_object() {
    let mut memory: Box<dyn TableMemory> = Box::new(ObjectStore::new());
    let bytes = vec![0, 1, 2, 254, 255];

    let array_id =
        create_byte_array(&mut *memory, &bytes).expect("byte array creation should succeed");
    let roundtrip = extract_byte_array(&mut *memory, &Value::from(ArrayRef::new(array_id)))
        .expect("byte array extraction should succeed");

    assert_eq!(roundtrip, bytes);
}

#[test]
fn share_get_party_id_rejects_non_share_objects() {
    let mut vm = VirtualMachine::builder().with_mpc_builtins(false).build();
    register_mpc_builtins(&mut vm);

    let object_id = vm
        .create_object_ref()
        .expect("create non-share object")
        .id();
    let object = Value::from(ObjectRef::new(object_id));
    vm.set_table_field(
        TableRef::object(object_id),
        Value::String(share_fields::PARTY_ID.to_string()),
        Value::I64(12),
    )
    .expect("set misleading party ID field");

    let err = vm
        .execute_with_args("Share.get_party_id", &[object])
        .expect_err("non-share object must not expose Share metadata");
    let err = err.to_string();

    assert!(
        err.contains("Object is not a Share"),
        "unexpected error: {err}"
    );
}

#[test]
fn share_get_party_id_rejects_raw_shares_without_mpc_engine() {
    let mut vm = VirtualMachine::builder().with_mpc_builtins(false).build();
    register_mpc_builtins(&mut vm);

    let raw_share = Value::Share(ShareType::secret_int(64), ShareData::Opaque(vec![1, 2, 3]));
    let err = vm
        .execute_with_args("Share.get_party_id", &[raw_share])
        .expect_err("raw share party ID must come from configured MPC engine");

    assert_eq!(err.kind(), VirtualMachineErrorKind::ForeignFunction);
    assert_eq!(
        callback_runtime_kind(&err),
        Some(VirtualMachineErrorKind::Mpc)
    );
    assert!(
        err.to_string().contains("MPC engine not configured"),
        "unexpected error: {err}"
    );
}

#[test]
fn share_open_exp_rejects_engine_without_support() {
    let mut vm = VirtualMachine::builder().with_mpc_builtins(false).build();
    register_mpc_builtins(&mut vm);
    vm.set_mpc_engine(Arc::new(NoOpenExpEngine));

    let share_value = vm
        .create_share_object(
            ShareType::secret_int(64),
            ShareData::Opaque(vec![1, 2, 3, 4]),
            0,
        )
        .expect("share object creation should succeed");

    let fn_call = VMFunction::new(
        "test_share_open_exp".to_string(),
        vec![],
        Vec::new(),
        None,
        4,
        vec![
            Instruction::LDI(0, share_value),
            Instruction::LDI(1, Value::String("bls12-381-g1".to_string())),
            Instruction::PUSHARG(0),
            Instruction::PUSHARG(1),
            Instruction::CALL("Share.open_exp".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );
    vm.register_function(fn_call);

    let err = vm
        .execute("test_share_open_exp")
        .expect_err("Share.open_exp should fail for engines without exponent-open support");
    assert_eq!(err.kind(), VirtualMachineErrorKind::ForeignFunction);
    assert_eq!(
        callback_runtime_kind(&err),
        Some(VirtualMachineErrorKind::Mpc)
    );
    let err = err.to_string();

    assert!(
        err.contains("does not support Share.open_exp"),
        "expected capability error, got: {}",
        err
    );
}

#[test]
fn share_open_exp_uses_group_backend_for_bls12381_g2() {
    let mut vm = VirtualMachine::builder().with_mpc_builtins(false).build();
    register_mpc_builtins(&mut vm);

    let group_seen = Arc::new(Mutex::new(None));
    vm.set_mpc_engine(Arc::new(RecordingOpenExpEngine {
        group_seen: Arc::clone(&group_seen),
    }));

    let share_value = vm
        .create_share_object(
            ShareType::secret_int(64),
            ShareData::Opaque(vec![1, 2, 3, 4]),
            0,
        )
        .expect("share object creation should succeed");

    let fn_call = VMFunction::new(
        "test_share_open_exp_g2".to_string(),
        vec![],
        Vec::new(),
        None,
        4,
        vec![
            Instruction::LDI(0, share_value),
            Instruction::LDI(1, Value::String("bls12-381-g2".to_string())),
            Instruction::PUSHARG(0),
            Instruction::PUSHARG(1),
            Instruction::CALL("Share.open_exp".to_string()),
            Instruction::RET(0),
        ],
        HashMap::new(),
    );
    vm.register_function(fn_call);

    let result = vm
        .execute("test_share_open_exp_g2")
        .expect("Share.open_exp should use the group-aware backend hook");
    let bytes = vm
        .read_byte_array(&result)
        .expect("Share.open_exp should return a byte array");

    assert_eq!(bytes, vec![5, 6, 7, 8]);
    assert_eq!(
        *group_seen
            .lock()
            .expect("group recording lock should not be poisoned"),
        Some(MpcExponentGroup::Bls12381G2)
    );
}
