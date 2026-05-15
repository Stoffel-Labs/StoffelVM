use super::*;
use crate::net::curve::MpcCurveConfig;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use stoffel_vm_types::core_types::{ClearShareInput, ClearShareValue, ShareData, ShareType};

struct CapabilityOnlyEngine {
    capabilities: MpcCapabilities,
}

impl CapabilityOnlyEngine {
    fn new(capabilities: MpcCapabilities) -> Self {
        Self { capabilities }
    }
}

impl MpcEngine for CapabilityOnlyEngine {
    fn protocol_name(&self) -> &'static str {
        "capability-only"
    }

    fn topology(&self) -> MpcSessionTopology {
        MpcSessionTopology::try_new(0, 0, 1, 0).expect("test topology should be valid")
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
        self.capabilities
    }
}

#[async_trait::async_trait]
impl AsyncMpcEngine for CapabilityOnlyEngine {
    async fn open_share_async(
        &self,
        _ty: ShareType,
        _share_bytes: &[u8],
    ) -> MpcEngineResult<ClearShareValue> {
        Err(MpcEngineError::operation_failed(
            "async_open_share",
            "not implemented",
        ))
    }
}

#[test]
fn runtime_info_snapshots_engine_metadata_without_exposing_backend_ops() {
    let engine =
        CapabilityOnlyEngine::new(MpcCapabilities::CLIENT_INPUT | MpcCapabilities::RANDOMNESS);

    let info = MpcRuntimeInfo::from_engine(&engine);

    assert_eq!(info.protocol_name(), "capability-only");
    assert_eq!(
        engine.try_topology(),
        Ok(MpcSessionTopology::try_new(0, 0, 1, 0).unwrap())
    );
    assert_eq!(engine.instance(), MpcInstanceId::new(0));
    assert_eq!(engine.party_count(), MpcPartyCount::one());
    assert_eq!(engine.threshold_param(), MpcThreshold::new(0));
    assert_eq!(info.topology(), engine.topology());
    assert_eq!(info.instance(), MpcInstanceId::new(0));
    assert_eq!(info.party(), MpcPartyId::new(0));
    assert_eq!(info.party_count(), MpcPartyCount::one());
    assert_eq!(info.threshold_param(), MpcThreshold::new(0));
    assert_eq!(info.curve_config(), MpcCurveConfig::default());
    assert_eq!(info.field_kind(), MpcCurveConfig::default().field_kind());
    assert_eq!(
        info.capabilities(),
        MpcCapabilities::CLIENT_INPUT | MpcCapabilities::RANDOMNESS
    );
    assert!(info.has_capability(MpcCapability::ClientInput));
    assert!(!info.has_capability(MpcCapability::Multiplication));
    assert!(info.is_ready());
    assert_eq!(info.identity(), MpcEngineIdentity::from_engine(&engine));
    assert_eq!(info.identity().topology(), info.topology());
    assert_eq!(info.identity().party(), MpcPartyId::new(0));
}

#[tokio::test]
async fn default_async_input_share_requires_explicit_override() {
    let engine = CapabilityOnlyEngine::new(MpcCapabilities::empty());
    let input = ClearShareInput::new(
        ShareType::default_secret_int(),
        ClearShareValue::Integer(42),
    );

    let err = engine
        .input_share_async(input)
        .await
        .expect_err("default async input sharing should not call sync input_share");

    let err = err.to_string();
    assert!(
        err.contains("input_share_async") && err.contains("synchronous bridge"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn default_async_capability_methods_require_explicit_override() {
    let engine = CapabilityOnlyEngine::new(MpcCapabilities::MULTIPLICATION);

    let err = engine
        .multiply_share_async(ShareType::default_secret_int(), &[1], &[2])
        .await
        .expect_err("default async multiplication should not call sync multiplication ops");

    let err = err.to_string();
    assert!(
        err.contains("advertises multiplication")
            && err.contains("multiply_share_async")
            && err.contains("synchronous bridge"),
        "unexpected error: {err}"
    );
}

#[test]
fn session_topology_revalidates_typed_parts() {
    let party_count = MpcPartyCount::new(NonZeroUsize::new(3).unwrap());

    assert!(matches!(
        MpcSessionTopology::try_from_typed(
            MpcInstanceId::new(1),
            MpcPartyId::new(3),
            party_count,
            MpcThreshold::new(1),
        ),
        Err(MpcSessionTopologyError::PartyOutOfRange {
            party_id: 3,
            n_parties: 3
        })
    ));

    assert!(matches!(
        MpcSessionTopology::try_from_typed(
            MpcInstanceId::new(1),
            MpcPartyId::new(1),
            party_count,
            MpcThreshold::new(3),
        ),
        Err(MpcSessionTopologyError::ThresholdOutOfRange {
            threshold: 3,
            n_parties: 3
        })
    ));
}

#[test]
fn capabilities_expose_stable_vm_names() {
    let capabilities =
        MpcCapabilities::OPEN_IN_EXP | MpcCapabilities::FIELD_OPEN | MpcCapabilities::RANDOMNESS;

    assert_eq!(
        capabilities
            .iter_supported()
            .map(MpcCapability::as_str)
            .collect::<Vec<_>>(),
        vec!["open-in-exponent", "randomness", "field-open"]
    );
    assert_eq!(
        MpcCapability::parse_name("open_in_exp"),
        Ok(MpcCapability::OpenInExponent)
    );
    assert_eq!(
        MpcCapability::parse_name("preproc-persistence"),
        Ok(MpcCapability::PreprocPersistence)
    );
    assert_eq!(
        MpcCapability::parse_name("garbage"),
        Err(MpcCapabilityError::UnsupportedCapability {
            name: "garbage".to_string()
        })
    );
}

struct NativeOpenExpEngine {
    curve_config: MpcCurveConfig,
    open_calls: AtomicUsize,
    async_open_calls: AtomicUsize,
}

impl NativeOpenExpEngine {
    fn new(curve_config: MpcCurveConfig) -> Self {
        Self {
            curve_config,
            open_calls: AtomicUsize::new(0),
            async_open_calls: AtomicUsize::new(0),
        }
    }
}

impl MpcEngine for NativeOpenExpEngine {
    fn protocol_name(&self) -> &'static str {
        "native-open-exp"
    }

    fn topology(&self) -> MpcSessionTopology {
        MpcSessionTopology::try_new(0, 0, 1, 0).expect("test topology should be valid")
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

    fn curve_config(&self) -> MpcCurveConfig {
        self.curve_config
    }

    fn capabilities(&self) -> MpcCapabilities {
        MpcCapabilities::OPEN_IN_EXP
    }

    fn as_open_in_exp(&self) -> Option<&dyn MpcEngineOpenInExponent> {
        Some(self)
    }
}

impl MpcEngineOpenInExponent for NativeOpenExpEngine {
    fn open_share_in_exp(
        &self,
        _ty: ShareType,
        _share_bytes: &[u8],
        _generator_bytes: &[u8],
    ) -> MpcEngineResult<Vec<u8>> {
        self.open_calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![9, 8, 7])
    }
}

#[async_trait::async_trait]
impl AsyncMpcEngine for NativeOpenExpEngine {
    async fn open_share_async(
        &self,
        _ty: ShareType,
        _share_bytes: &[u8],
    ) -> MpcEngineResult<ClearShareValue> {
        Err(MpcEngineError::operation_failed(
            "open_share_async",
            "not implemented",
        ))
    }

    async fn open_share_in_exp_async(
        &self,
        _ty: ShareType,
        _share_bytes: &[u8],
        _generator_bytes: &[u8],
    ) -> MpcEngineResult<Vec<u8>> {
        self.async_open_calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![3, 2, 1])
    }
}

#[test]
fn multiplication_ops_reports_capability_subtrait_mismatch() {
    let engine = CapabilityOnlyEngine::new(MpcCapabilities::MULTIPLICATION);

    let err = match engine.multiplication_ops() {
        Ok(_) => panic!("engine should not expose multiplication ops"),
        Err(err) => err,
    };

    assert_eq!(
        err,
        MpcEngineError::CapabilityUnavailable {
            protocol_name: "capability-only".to_string(),
            capability: MpcCapability::Multiplication,
            advertised: true,
        }
    );
    let err = err.to_string();
    assert!(err.contains("advertises multiplication"));
    assert!(err.contains("MpcEngineMultiplication"));
}

#[test]
fn multiplication_ops_reports_unsupported_backend() {
    let engine = CapabilityOnlyEngine::new(MpcCapabilities::empty());

    let err = match engine.multiplication_ops() {
        Ok(_) => panic!("engine should not expose multiplication ops"),
        Err(err) => err,
    };

    let err = err.to_string();
    assert!(err.contains("does not support multiplication"));
}

#[test]
fn consensus_ops_reports_capability_subtrait_mismatch() {
    let engine = CapabilityOnlyEngine::new(MpcCapabilities::CONSENSUS);

    let err = match engine.consensus_ops() {
        Ok(_) => panic!("engine should not expose consensus ops"),
        Err(err) => err,
    };

    let err = err.to_string();
    assert!(err.contains("advertises consensus"));
    assert!(err.contains("MpcEngineConsensus"));
}

#[test]
fn client_ops_reports_unsupported_backend() {
    let engine = CapabilityOnlyEngine::new(MpcCapabilities::empty());

    let err = match engine.client_ops() {
        Ok(_) => panic!("engine should not expose client ops"),
        Err(err) => err,
    };

    let err = err.to_string();
    assert!(err.contains("does not support client input hydration"));
}

#[test]
fn client_output_ops_reports_capability_subtrait_mismatch() {
    let engine = CapabilityOnlyEngine::new(MpcCapabilities::CLIENT_OUTPUT);

    let err = match engine.client_output_ops() {
        Ok(_) => panic!("engine should not expose client output ops"),
        Err(err) => err,
    };

    let err = err.to_string();
    assert!(err.contains("advertises client output"));
    assert!(err.contains("MpcEngineClientOutput"));
}

#[test]
fn client_output_ops_reports_unsupported_backend() {
    let engine = CapabilityOnlyEngine::new(MpcCapabilities::empty());

    let err = match engine.client_output_ops() {
        Ok(_) => panic!("engine should not expose client output ops"),
        Err(err) => err,
    };

    let err = err.to_string();
    assert!(err.contains("does not support client output delivery"));
}

#[test]
fn open_in_exp_ops_reports_capability_subtrait_mismatch() {
    let engine = CapabilityOnlyEngine::new(MpcCapabilities::OPEN_IN_EXP);

    let err = match engine.open_in_exp_ops() {
        Ok(_) => panic!("engine should not expose open-in-exponent ops"),
        Err(err) => err,
    };

    let err = err.to_string();
    assert!(err.contains("advertises open-in-exponent"));
    assert!(err.contains("MpcEngineOpenInExponent"));
}

#[test]
fn open_in_exp_ops_reports_unsupported_backend() {
    let engine = CapabilityOnlyEngine::new(MpcCapabilities::empty());

    let err = match engine.open_in_exp_ops() {
        Ok(_) => panic!("engine should not expose open-in-exponent ops"),
        Err(err) => err,
    };

    let err = err.to_string();
    assert!(err.contains("does not support Share.open_exp"));
}

#[test]
fn randomness_ops_reports_capability_subtrait_mismatch() {
    let engine = CapabilityOnlyEngine::new(MpcCapabilities::RANDOMNESS);

    let err = match engine.randomness_ops() {
        Ok(_) => panic!("engine should not expose randomness ops"),
        Err(err) => err,
    };

    let err = err.to_string();
    assert!(err.contains("advertises randomness"));
    assert!(err.contains("MpcEngineRandomness"));
}

#[test]
fn randomness_ops_reports_unsupported_backend() {
    let engine = CapabilityOnlyEngine::new(MpcCapabilities::empty());

    let err = match engine.randomness_ops() {
        Ok(_) => panic!("engine should not expose randomness ops"),
        Err(err) => err,
    };

    let err = err.to_string();
    assert!(err.contains("does not support jointly-random share generation"));
}

#[test]
fn field_open_ops_reports_capability_subtrait_mismatch() {
    let engine = CapabilityOnlyEngine::new(MpcCapabilities::FIELD_OPEN);

    let err = match engine.field_open_ops() {
        Ok(_) => panic!("engine should not expose field-open ops"),
        Err(err) => err,
    };

    let err = err.to_string();
    assert!(err.contains("advertises field opening"));
    assert!(err.contains("MpcEngineFieldOpen"));
}

#[test]
fn field_open_ops_reports_unsupported_backend() {
    let engine = CapabilityOnlyEngine::new(MpcCapabilities::empty());

    let err = match engine.field_open_ops() {
        Ok(_) => panic!("engine should not expose field-open ops"),
        Err(err) => err,
    };

    let err = err.to_string();
    assert!(err.contains("does not support Share.open_field"));
}

#[test]
fn preproc_persistence_ops_reports_capability_subtrait_mismatch() {
    let engine = CapabilityOnlyEngine::new(MpcCapabilities::PREPROC_PERSISTENCE);

    let err = match engine.preproc_persistence_ops() {
        Ok(_) => panic!("engine should not expose preprocessing persistence ops"),
        Err(err) => err,
    };

    let err = err.to_string();
    assert!(err.contains("advertises preprocessing persistence"));
    assert!(err.contains("MpcEnginePreprocPersistence"));
}

#[test]
fn preproc_persistence_ops_reports_unsupported_backend() {
    let engine = CapabilityOnlyEngine::new(MpcCapabilities::empty());

    let err = match engine.preproc_persistence_ops() {
        Ok(_) => panic!("engine should not expose preprocessing persistence ops"),
        Err(err) => err,
    };

    let err = err.to_string();
    assert!(err.contains("does not support preprocessing persistence"));
}

#[test]
fn reservation_ops_reports_capability_subtrait_mismatch() {
    let engine = CapabilityOnlyEngine::new(MpcCapabilities::RESERVATION);

    let err = match engine.reservation_ops() {
        Ok(_) => panic!("engine should not expose reservation ops"),
        Err(err) => err,
    };

    let err = err.to_string();
    assert!(err.contains("advertises reservation"));
    assert!(err.contains("MpcEngineReservation"));
}

#[test]
fn exponent_generator_resolves_supported_curve_names() {
    let cases = [
        ("bls12-381-g1", MpcExponentGroup::Bls12381G1),
        ("bls12-381-g2", MpcExponentGroup::Bls12381G2),
        ("bn254-g1", MpcExponentGroup::Bn254G1),
        ("curve25519-edwards", MpcExponentGroup::Curve25519Edwards),
        ("ed25519-edwards", MpcExponentGroup::Ed25519Edwards),
    ];

    for (name, expected_group) in cases {
        let generator =
            MpcExponentGenerator::from_curve_name(name).expect("known curve should resolve");

        assert_eq!(generator.group(), expected_group);
        assert!(
            !generator.bytes().is_empty(),
            "{name} should serialize a default generator"
        );
    }
}

#[test]
fn exponent_generator_rejects_unknown_curve_names() {
    let err = MpcExponentGenerator::from_curve_name("unknown-curve")
        .expect_err("unknown curve should be rejected");

    assert_eq!(
        err,
        MpcExponentError::UnsupportedGroupName {
            name: "unknown-curve".to_string()
        }
    );
}

#[test]
fn default_open_exp_group_accepts_native_group() {
    let engine = NativeOpenExpEngine::new(MpcCurveConfig::Bls12_381);

    let result = engine
        .open_share_in_exp_group(
            MpcExponentGroup::Bls12381G1,
            ShareType::secret_int(64),
            &[1, 2, 3],
            &[4, 5, 6],
        )
        .expect("native exponent group should be accepted");

    assert_eq!(result, vec![9, 8, 7]);
    assert_eq!(engine.open_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn default_open_exp_group_rejects_non_native_group_without_dispatch() {
    let engine = NativeOpenExpEngine::new(MpcCurveConfig::Bls12_381);

    let err = engine
        .open_share_in_exp_group(
            MpcExponentGroup::Bn254G1,
            ShareType::secret_int(64),
            &[1, 2, 3],
            &[4, 5, 6],
        )
        .expect_err("non-native exponent group should be rejected");

    assert!(err
        .to_string()
        .contains("does not support Share.open_exp for bn254-g1"));
    assert_eq!(engine.open_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn default_async_open_exp_group_uses_async_native_path() {
    let engine = NativeOpenExpEngine::new(MpcCurveConfig::Bls12_381);

    let result = engine
        .open_share_in_exp_group_async(
            MpcExponentGroup::Bls12381G1,
            ShareType::secret_int(64),
            &[1, 2, 3],
            &[4, 5, 6],
        )
        .await
        .expect("native exponent group should be accepted asynchronously");

    assert_eq!(result, vec![3, 2, 1]);
    assert_eq!(engine.async_open_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        engine.open_calls.load(Ordering::SeqCst),
        0,
        "async group dispatch must not fall back to the sync exponent-open path"
    );
}

#[tokio::test]
async fn default_async_open_exp_group_rejects_non_native_group_without_dispatch() {
    let engine = NativeOpenExpEngine::new(MpcCurveConfig::Bls12_381);

    let err = engine
        .open_share_in_exp_group_async(
            MpcExponentGroup::Bn254G1,
            ShareType::secret_int(64),
            &[1, 2, 3],
            &[4, 5, 6],
        )
        .await
        .expect_err("non-native exponent group should be rejected");

    assert!(err
        .to_string()
        .contains("does not support Share.open_exp for bn254-g1"));
    assert_eq!(engine.async_open_calls.load(Ordering::SeqCst), 0);
    assert_eq!(engine.open_calls.load(Ordering::SeqCst), 0);
}
