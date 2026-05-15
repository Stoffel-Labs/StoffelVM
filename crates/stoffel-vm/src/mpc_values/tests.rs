use super::*;
use stoffel_vm_types::core_types::{
    ClearShareValue, ObjectStore, ShareData, ShareType, TableMemory, TableRef, Value, F64,
};

#[test]
fn clear_share_input_canonicalizes_integer_widths() {
    let input = clear_share_input(&Value::U8(7), None)
        .expect("u8 values should be valid clear share inputs");

    assert_eq!(input.share_type(), ShareType::default_secret_int());
    assert_eq!(input.value(), ClearShareValue::Integer(7));
}

#[test]
fn clear_share_input_rejects_unsigned_values_outside_i64_domain() {
    let err = clear_share_input(&Value::U64(i64::MAX as u64 + 1), None)
        .expect_err("oversized u64 must not be silently truncated");

    assert_eq!(
        err,
        MpcValueError::ValueConversion("clear integer exceeds i64 range".to_string())
    );
}

#[test]
fn clear_share_input_canonicalizes_explicit_fixed_point_integer_input() {
    let share_type = ShareType::default_secret_fixed_point();
    let input = clear_share_input(&Value::U16(42), Some(share_type))
        .expect("integer values should be canonicalized for fixed-point shares");

    assert_eq!(input.share_type(), share_type);
    assert_eq!(input.value(), ClearShareValue::FixedPoint(F64(42.0)));
}

#[test]
fn share_object_metadata_errors_are_typed() {
    let mut store = ObjectStore::new();
    let object_ref = store
        .create_object_ref()
        .expect("create malformed share object");
    let object = Value::from(object_ref);
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
        .expect("set invalid bit length");
    store
        .set_table_field(
            table_ref,
            Value::String(share_fields::DATA.to_string()),
            Value::Share(ShareType::default_secret_int(), ShareData::Opaque(vec![])),
        )
        .expect("set share data");

    let err = share_object::get_share_type(&mut store, &object).unwrap_err();

    assert_eq!(
        err,
        MpcValueError::ValueConversion("bit_length must be a non-negative integer".to_string())
    );
}

#[test]
fn share_object_party_id_errors_are_typed() {
    let mut store = ObjectStore::new();
    let share_ref = share_object::create_share_object_ref(
        &mut store,
        ShareType::default_secret_int(),
        ShareData::Opaque(vec![]),
        1,
    )
    .expect("create Share object");
    let object = Value::from(share_ref);
    store
        .set_table_field(
            TableRef::from(share_ref),
            Value::String(share_fields::PARTY_ID.to_string()),
            Value::I64(-1),
        )
        .expect("set invalid party ID");

    let err = share_object::get_party_id(&mut store, &object).unwrap_err();

    assert_eq!(
        err,
        MpcValueError::ValueConversion("party_id must be a non-negative integer".to_string())
    );
}

#[test]
fn share_object_typed_ref_helpers_avoid_value_wrapping() {
    let mut store = ObjectStore::new();
    let share_type = ShareType::default_secret_int();
    let share_data = ShareData::Opaque(vec![7, 8]);
    let share_ref =
        share_object::create_share_object_ref(&mut store, share_type, share_data.clone(), 3)
            .expect("create Share object");

    assert_eq!(
        share_object::ShareObjectRef::validate(&mut store, share_ref.object_ref()),
        Ok(share_ref)
    );
    assert_eq!(Value::from(share_ref), Value::from(share_ref.object_ref()));
    assert_eq!(
        TableRef::from(share_ref),
        TableRef::from(share_ref.object_ref())
    );
    assert!(share_object::is_share_object_ref(&mut store, share_ref));
    assert_eq!(
        share_object::extract_share_data_ref(&mut store, share_ref),
        Ok((share_type, share_data.clone()))
    );
    assert_eq!(
        share_object::get_share_type_ref(&mut store, share_ref),
        Ok(share_type)
    );
    assert_eq!(share_object::get_party_id_ref(&mut store, share_ref), Ok(3));

    let array_ref = store.create_array_ref().expect("create share array");
    store
        .push_array_ref_values(array_ref, &[Value::from(share_ref)])
        .expect("push share object");

    assert_eq!(
        share_object::extract_share_array_ref(&mut store, array_ref, "typed shares"),
        Ok(vec![(share_type, share_data.clone())])
    );
    assert_eq!(
        share_object::extract_homogeneous_share_array_ref(&mut store, array_ref, "typed shares"),
        Ok(Some((share_type, vec![share_data])))
    );

    let plain_ref = store.create_object_ref().expect("create plain object");
    assert!(share_object::ShareObjectRef::validate(&mut store, plain_ref).is_err());
}

#[test]
fn share_array_extraction_reports_missing_elements() {
    let mut store = ObjectStore::new();
    let share_ref = share_object::create_share_object_ref(
        &mut store,
        ShareType::default_secret_int(),
        ShareData::Opaque(vec![1]),
        0,
    )
    .expect("create Share object");
    let array_ref = store.create_array_ref().expect("create share array");
    let array = Value::from(array_ref);
    store
        .set_table_field(
            TableRef::from(array_ref),
            Value::I64(1),
            Value::from(share_ref),
        )
        .expect("set sparse share element");

    let err = share_object::extract_share_array(&mut store, &array, "test shares").unwrap_err();

    assert_eq!(
        err,
        MpcValueError::MissingArrayElement {
            context: "test shares".to_string(),
            index: 0,
        }
    );
}

#[test]
fn homogeneous_share_array_rejects_type_mismatch() {
    let mut store = ObjectStore::new();
    let int_share_ref = share_object::create_share_object_ref(
        &mut store,
        ShareType::default_secret_int(),
        ShareData::Opaque(vec![1]),
        0,
    )
    .expect("create integer Share object");
    let fixed_share_ref = share_object::create_share_object_ref(
        &mut store,
        ShareType::default_secret_fixed_point(),
        ShareData::Opaque(vec![2]),
        0,
    )
    .expect("create fixed-point Share object");
    let array_ref = store.create_array_ref().expect("create share array");
    store
        .push_array_ref_values(
            array_ref,
            &[Value::from(int_share_ref), Value::from(fixed_share_ref)],
        )
        .expect("push share values");

    let err = share_object::extract_homogeneous_share_array(
        &mut store,
        &Value::from(array_ref),
        "test shares",
    )
    .unwrap_err();
    let err = err.to_string();

    assert!(
        err.contains("All shares must have the same type") && err.contains("element 1"),
        "unexpected error: {err}"
    );
}

#[test]
fn matching_share_pair_reports_typed_mismatch_context() {
    let mut store = ObjectStore::new();
    let left_ref = share_object::create_share_object_ref(
        &mut store,
        ShareType::default_secret_int(),
        ShareData::Opaque(vec![1]),
        0,
    )
    .expect("create integer Share object");
    let right_ref = share_object::create_share_object_ref(
        &mut store,
        ShareType::default_secret_fixed_point(),
        ShareData::Opaque(vec![2]),
        0,
    )
    .expect("create fixed-point Share object");

    let err = share_object::extract_matching_share_pair(
        &mut store,
        &Value::from(left_ref),
        &Value::from(right_ref),
        "Share.add",
    )
    .unwrap_err();

    assert_eq!(
        err,
        MpcValueError::ShareTypeMismatch {
            context: "Share.add".to_string(),
            left: ShareType::default_secret_int(),
            right: ShareType::default_secret_fixed_point(),
        }
    );
}

#[cfg(feature = "avss")]
#[test]
fn avss_object_shape_errors_are_typed() {
    let mut store = ObjectStore::new();
    let object_ref = store
        .create_object_ref()
        .expect("create malformed AVSS object");
    let object = Value::from(object_ref);
    let table_ref = TableRef::from(object_ref);
    store
        .set_table_field(
            table_ref,
            Value::String(avss_fields::TYPE.to_string()),
            Value::String(avss_fields::TYPE_VALUE.to_string()),
        )
        .expect("set AVSS type tag");
    store
        .set_table_field(
            table_ref,
            Value::String(avss_fields::KEY_NAME.to_string()),
            Value::I64(7),
        )
        .expect("set invalid key name");

    let err = avss_object::get_key_name(&mut store, &object).unwrap_err();

    assert_eq!(
        err,
        MpcValueError::UnexpectedValue {
            context: "AVSS __key_name field".to_string(),
            expected: "String".to_string(),
            actual: Value::I64(7),
        }
    );
}

#[cfg(feature = "avss")]
#[test]
fn avss_commitment_bounds_errors_are_typed() {
    let mut store = ObjectStore::new();
    let avss_ref = avss_object::create_avss_share_object_ref(
        &mut store,
        "test-key",
        vec![1, 2, 3],
        vec![vec![4, 5, 6]],
        1,
    )
    .expect("create AVSS object");
    let object = Value::from(avss_ref);

    let err = avss_object::get_commitment(&mut store, &object, 1).unwrap_err();

    assert_eq!(
        err,
        MpcValueError::IndexOutOfBounds {
            context: "AVSS commitments".to_string(),
            index: 1,
            len: 1,
        }
    );
}

#[cfg(feature = "avss")]
#[test]
fn avss_typed_ref_helpers_avoid_value_wrapping() {
    let mut store = ObjectStore::new();
    let object_ref = avss_object::create_avss_share_object_ref(
        &mut store,
        "test-key",
        vec![1, 2, 3],
        vec![vec![4, 5, 6]],
        1,
    )
    .expect("create AVSS object");

    assert_eq!(
        avss_object::AvssShareObjectRef::validate(&mut store, object_ref.object_ref()),
        Ok(object_ref)
    );
    assert_eq!(
        Value::from(object_ref),
        Value::from(object_ref.object_ref())
    );
    assert_eq!(
        TableRef::from(object_ref),
        TableRef::from(object_ref.object_ref())
    );
    assert!(avss_object::is_avss_share_object_ref(
        &mut store, object_ref
    ));
    assert_eq!(
        avss_object::get_key_name_ref(&mut store, object_ref),
        Ok("test-key".to_string())
    );
    assert_eq!(
        avss_object::get_commitment_count_ref(&mut store, object_ref),
        Ok(1)
    );
    assert_eq!(
        avss_object::get_commitment_ref(&mut store, object_ref, 0),
        Ok(vec![4, 5, 6])
    );

    let plain_ref = store.create_object_ref().expect("create plain object");
    assert!(avss_object::AvssShareObjectRef::validate(&mut store, plain_ref).is_err());
}
