use crate::core_vm::VirtualMachine;
use crate::net::curve::SupportedMpcField;
use crate::net::engine_config::MpcSessionConfig;
use crate::net::mpc::avss::{AvssEngineConfig, AvssMpcEngine};
use crate::net::mpc::honeybadger::{
    HoneyBadgerEngineConfig, HoneyBadgerMpcEngine, HoneyBadgerPreprocessingConfig,
};
use crate::net::mpc_engine::{AsyncMpcEngine, MpcEngine};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::Field;
use ark_serialize::CanonicalDeserialize;
use std::sync::Arc;
use stoffel_vm_types::compiled_binary::MpcBackend;
use stoffel_vm_types::core_types::{ArrayRef, ShareData, ShareType, TableRef, Value};
use stoffelmpc_mpc::common::share::avss::verify_feldman;
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::common::SecretSharingScheme;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelnet::transports::quic::QuicNetworkManager;

fn program<E: MpcEngine + 'static>(
    engine: Arc<E>,
    source: &str,
    backend: MpcBackend,
    level: u8,
) -> VirtualMachine {
    let options = stoffellang::CompilerOptions {
        optimize: level > 0,
        optimization_level: level,
        mpc_backend: backend,
        ..Default::default()
    };
    let compiled = stoffellang::compile(source, "field-regression.stfl", &options).unwrap();
    let mut vm = VirtualMachine::builder().with_mpc_engine(engine).build();
    for function in stoffellang::convert_to_binary(&compiled)
        .try_to_vm_functions()
        .unwrap()
    {
        vm.try_register_function(function).unwrap();
    }
    vm
}

async fn run<E: AsyncMpcEngine + 'static>(
    engine: Arc<E>,
    source: &str,
    backend: MpcBackend,
    asynchronous: bool,
) -> (VirtualMachine, Value) {
    let mut vm = program(
        engine.clone(),
        source,
        backend,
        if asynchronous { 3 } else { 0 },
    );
    let value = if asynchronous {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            vm.execute_async("main", engine.as_ref()),
        )
        .await
        .expect("local constant operation must not communicate")
        .unwrap()
    } else {
        vm.execute("main").unwrap()
    };
    (vm, value)
}

async fn exercise_backend<E, F, G>(engine: Arc<E>, backend: MpcBackend)
where
    E: AsyncMpcEngine + 'static,
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F>,
{
    engine.start().unwrap();
    for asynchronous in [false, true] {
        for field in [
            "Field.zero()",
            "Field.one()",
            "Field.neg(Field.one())",
            "Field.mul(Field.from_int(4294967296), Field.from_int(4294967296))",
        ] {
            let source = format!("def main() -> Share:\n  var f: bytes = {field}\n  var s: Share = Share.from_field(f)\n  assert(Share.get_type(s) == \"SecretField\")\n  return s\n");
            let (mut vm, value) = run(engine.clone(), &source, backend, asynchronous).await;
            let (ty, data) = vm.read_share_object(&value).unwrap();
            assert_eq!(ty, ShareType::SecretField);
            // A public constant has the same field value at every party's
            // evaluation point. Multi-party recovery is checked separately.
            let clear = match backend {
                MpcBackend::HoneyBadger => {
                    RobustShare::<F>::deserialize_compressed(data.as_bytes())
                        .unwrap()
                        .share[0]
                }
                MpcBackend::Avss => {
                    let share = FeldmanShamirShare::<F, G>::deserialize_compressed(data.as_bytes())
                        .unwrap();
                    assert!(verify_feldman(share.clone(), share.feldmanshare.id));
                    share.feldmanshare.share[0]
                }
            };
            let mut actual = Vec::new();
            clear.serialize_compressed(&mut actual).unwrap();
            let source = format!("def main() -> bytes:\n  return {field}\n");
            let (mut clear_vm, clear_value) =
                run(engine.clone(), &source, backend, asynchronous).await;
            assert_eq!(actual, clear_vm.read_byte_array(&clear_value).unwrap());
        }
        for expr in [
            "Share.add_field(s, Field.one())",
            "Share.mul_field(s, Field.one())",
            "s + s",
            "s - s",
            "s * 2",
            "2 * s",
            "s / 2",
            "Share.neg(s)",
        ] {
            let source = format!("def main() -> string:\n  var s = Share.from_field(Field.one())\n  return Share.get_type({expr})\n");
            let (_, value) = run(engine.clone(), &source, backend, asynchronous).await;
            assert_eq!(value, Value::String("SecretField".to_owned()), "{expr}");
        }
        for expr in [
            "Share.open(s)",
            "Share.retag(s, 1)",
            "Share.mul_scalar(s, 1.5)",
            "Share.add_constant(s, 1.5)",
            "s + Share.from_clear_int(1, 64)",
            "Share.batch_open([s])",
            "Share.batch_open_field([s, Share.from_clear_int(1, 64)])",
            "Share.add_field(Share.from_clear_fixed(1.0, 64, 16), Field.one())",
            "Share.mul_field(Share.from_clear_fixed(1.0, 64, 16), Field.one())",
        ] {
            let source =
                format!("def main():\n  var s = Share.from_field(Field.one())\n  discard {expr}\n");
            let mut vm = program(engine.clone(), &source, backend, 0);
            let result = if asynchronous {
                vm.execute_async("main", engine.as_ref()).await
            } else {
                vm.execute("main")
            };
            assert!(result.is_err(), "{expr}");
        }
        for bytes in [
            "[]",
            "[0]",
            "Field.one() + padding",
            "[255u8] * len(Field.one())",
        ] {
            let source = format!(
                "def main():\n  var padding: bytes = [0]\n  discard Share.from_field({bytes})\n"
            );
            let mut vm = program(engine.clone(), &source, backend, 0);
            let result = if asynchronous {
                vm.execute_async("main", engine.as_ref()).await
            } else {
                vm.execute("main")
            };
            assert!(result.is_err(), "{bytes}");
        }
    }
}

async fn roundtrips_for_curve<F, G>()
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    let session =
        MpcSessionConfig::try_new(97100, 0, 5, 1, Arc::new(QuicNetworkManager::new())).unwrap();
    let hb = HoneyBadgerMpcEngine::<F, G>::from_config(HoneyBadgerEngineConfig::new(
        session,
        HoneyBadgerPreprocessingConfig::new(0, 0),
    ))
    .unwrap();
    exercise_backend::<_, F, G>(hb, MpcBackend::HoneyBadger).await;
    let session =
        MpcSessionConfig::try_new(97200, 0, 5, 1, Arc::new(QuicNetworkManager::new())).unwrap();
    let avss = AvssMpcEngine::<F, G>::from_config(
        AvssEngineConfig::new(session, F::from(1u64), Arc::new(vec![G::generator(); 5]))
            .with_preprocessing_counts(0, 0),
    )
    .await
    .unwrap();
    exercise_backend::<_, F, G>(avss, MpcBackend::Avss).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn from_field_roundtrips_and_errors_bls12_381() {
    roundtrips_for_curve::<ark_bls12_381::Fr, ark_bls12_381::G1Projective>().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn from_field_roundtrips_and_errors_bn254() {
    roundtrips_for_curve::<ark_bn254::Fr, ark_bn254::G1Projective>().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn from_field_multi_party_constants_preserve_payload_and_commitments() {
    type F = ark_bls12_381::Fr;
    type G = ark_bls12_381::G1Projective;
    let expected = F::from(4294967296u64).square();
    let source = "def main() -> Share:\n  return Share.from_field(Field.mul(Field.from_int(4294967296), Field.from_int(4294967296)))\n";
    let mut robust = Vec::new();
    let mut feldman = Vec::new();
    for party in 0..5 {
        let session =
            MpcSessionConfig::try_new(97300, party, 5, 1, Arc::new(QuicNetworkManager::new()))
                .unwrap();
        let hb = HoneyBadgerMpcEngine::<F, G>::from_config(HoneyBadgerEngineConfig::new(
            session,
            HoneyBadgerPreprocessingConfig::new(0, 0),
        ))
        .unwrap();
        hb.start().unwrap();
        let (mut vm, value) = run(hb, source, MpcBackend::HoneyBadger, true).await;
        let (ty, data) = vm.read_share_object(&value).unwrap();
        assert_eq!(ty, ShareType::SecretField);
        let share = RobustShare::<F>::deserialize_compressed(data.as_bytes()).unwrap();
        assert_eq!(share.share[0], expected);
        assert_eq!(share.id, party);
        assert_eq!(share.degree, 1);
        robust.push(share);

        let session =
            MpcSessionConfig::try_new(97400, party, 5, 1, Arc::new(QuicNetworkManager::new()))
                .unwrap();
        let avss = AvssMpcEngine::<F, G>::from_config(
            AvssEngineConfig::new(session, F::from(1u64), Arc::new(vec![G::generator(); 5]))
                .with_preprocessing_counts(0, 0),
        )
        .await
        .unwrap();
        avss.start().unwrap();
        let (mut vm, value) = run(avss, source, MpcBackend::Avss, true).await;
        let (ty, data) = vm.read_share_object(&value).unwrap();
        assert_eq!(ty, ShareType::SecretField);
        assert!(matches!(data, ShareData::Feldman { .. }));
        let share = FeldmanShamirShare::<F, G>::deserialize_compressed(data.as_bytes()).unwrap();
        assert_eq!(share.feldmanshare.share[0], expected);
        assert!(verify_feldman(share.clone(), share.feldmanshare.id));
        assert_eq!(share.commitments[0], G::generator() * expected);
        assert_eq!(share.commitments.len(), 2);
        feldman.push(share);
    }
    assert_eq!(
        RobustShare::recover_secret(&robust, 5, 1).unwrap().1,
        expected
    );
    assert_eq!(
        FeldmanShamirShare::recover_secret(&feldman, 5, 1)
            .unwrap()
            .1,
        expected
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn from_field_roundtrips_and_errors_other_curves() {
    roundtrips_for_curve::<ark_curve25519::Fr, ark_curve25519::EdwardsProjective>().await;
    roundtrips_for_curve::<ark_ed25519::Fr, ark_ed25519::EdwardsProjective>().await;
    roundtrips_for_curve::<ark_secp256k1::Fr, ark_secp256k1::Projective>().await;
    roundtrips_for_curve::<ark_secp256r1::Fr, ark_secp256r1::Projective>().await;
}

// Each party has its own registry, as in a real deployment. Replay canonical
// opening frames made from the five real constructor payloads; no QUIC peers
// or preprocessing are needed to exercise VM dispatch and reconstruction.
async fn field_openings<E: AsyncMpcEngine + 'static>(
    engines: Vec<Arc<E>>,
    routers: Vec<Arc<crate::net::open_registry::OpenMessageRouter>>,
    backend: MpcBackend,
    instance: u64,
) {
    let prefix = "def main() -> list[Share]:\n  var f = Field.mul(Field.from_int(4294967296), Field.from_int(4294967296))\n  var s = Share.from_field(f)\n";
    let prepare = format!("{prefix}  return [s, s + s, s * 2, s / 2, Share.add_field(Share.from_clear_int(1, 64), f), s, Share.neg(s)]\n");
    let mut payloads = Vec::new();
    for engine in &engines {
        engine.start().unwrap();
        let (mut vm, value) = run(engine.clone(), &prepare, backend, true).await;
        let array = ArrayRef::try_from(&value).unwrap();
        let values: Vec<_> = (0..vm.read_array_ref_len(array).unwrap())
            .map(|index| {
                vm.read_table_field(TableRef::from(array), &Value::I64(index as i64))
                    .unwrap()
                    .unwrap()
            })
            .collect();
        let data: Vec<_> = values
            .iter()
            .map(|value| vm.read_share_object(value).unwrap().1.as_bytes().to_vec())
            .collect();
        payloads.push(data);
    }
    let type_key = match backend {
        MpcBackend::HoneyBadger => "hb-field-field",
        MpcBackend::Avss => "avss-field-field",
    };
    for (receiver, router) in routers.iter().enumerate() {
        for (sender, data) in payloads.iter().enumerate() {
            if receiver == sender {
                continue;
            }
            let count = if backend == MpcBackend::HoneyBadger {
                5
            } else {
                7
            };
            for (sequence, share) in data.iter().take(count).enumerate() {
                let wire = crate::net::open_registry::encode_single_share_wire_message(
                    instance, sequence, type_key, sender, share,
                )
                .unwrap();
                assert!(router.try_handle_wire_message(sender, &wire).unwrap());
            }
            if backend == MpcBackend::HoneyBadger {
                let wire = crate::net::open_registry::encode_batch_share_wire_message(
                    instance,
                    0,
                    "hb-batch-field-field",
                    sender,
                    &data[5..],
                )
                .unwrap();
                assert!(router.try_handle_wire_message(sender, &wire).unwrap());
            }
        }
    }
    let source = "def main() -> bool:\n  var f = Field.mul(Field.from_int(4294967296), Field.from_int(4294967296))\n  var s = Share.from_field(f)\n  assert(Share.open_field(s) == f)\n  assert(Share.open_field(s + s) == Field.add(f, f))\n  assert(Share.open_field(s * 2) == Field.mul(f, Field.from_int(2)))\n  assert(Share.open_field(s / 2) == Field.mul(f, Field.inverse(Field.from_int(2))))\n  assert(Share.open_field(Share.add_field(Share.from_clear_int(1, 64), f)) == Field.add(f, Field.one()))\n  var opened = Share.batch_open_field([s, Share.neg(s)])\n  return opened[0] == f and opened[1] == Field.neg(f)\n";
    for engine in engines {
        assert_eq!(
            run(engine, source, backend, true).await.1,
            Value::Bool(true)
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn from_field_five_party_raw_and_batch_opening() {
    type F = ark_bls12_381::Fr;
    type G = ark_bls12_381::G1Projective;
    let mut hb_engines = Vec::new();
    let mut avss_engines = Vec::new();
    let mut hb_routers = Vec::new();
    let mut avss_routers = Vec::new();
    for party in 0..5 {
        let router = Arc::new(crate::net::open_registry::OpenMessageRouter::new());
        let session =
            MpcSessionConfig::try_new(97500, party, 5, 1, Arc::new(QuicNetworkManager::new()))
                .unwrap()
                .with_open_message_router(router.clone());
        hb_engines.push(
            HoneyBadgerMpcEngine::<F, G>::from_config(HoneyBadgerEngineConfig::new(
                session,
                HoneyBadgerPreprocessingConfig::new(0, 0),
            ))
            .unwrap(),
        );
        hb_routers.push(router);
        let router = Arc::new(crate::net::open_registry::OpenMessageRouter::new());
        let session =
            MpcSessionConfig::try_new(97600, party, 5, 1, Arc::new(QuicNetworkManager::new()))
                .unwrap()
                .with_open_message_router(router.clone());
        avss_engines.push(
            AvssMpcEngine::<F, G>::from_config(
                AvssEngineConfig::new(session, F::from(1u64), Arc::new(vec![G::generator(); 5]))
                    .with_preprocessing_counts(0, 0),
            )
            .await
            .unwrap(),
        );
        avss_routers.push(router);
    }
    field_openings(hb_engines, hb_routers, MpcBackend::HoneyBadger, 97500).await;
    field_openings(avss_engines, avss_routers, MpcBackend::Avss, 97600).await;
}
