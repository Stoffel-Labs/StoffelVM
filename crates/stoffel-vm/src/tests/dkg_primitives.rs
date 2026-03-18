//! Tests for DKG primitive operations: `random_share` and `open_share_in_exp`.
//!
//! These tests verify the new primitives that enable DKG as a StoffelLang program:
//! - `Mpc.rand()` → `random_share` on the engine
//! - `Share.open_exp(share, curve)` → `open_share_in_exp` on the engine

use ark_bls12_381::{Fr, G1Projective as G1};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_serialize::CanonicalSerialize;
use std::sync::Arc;
use std::time::Duration;
use stoffel_vm_types::core_types::ShareType;
use stoffelmpc_mpc::common::{MPCProtocol, SecretSharingScheme};
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;

use crate::net::hb_engine::HoneyBadgerMpcEngine;
use crate::net::mpc_engine::MpcEngine;
use crate::tests::mpc_multiplication_integration::{
    setup_honeybadger_quic_network, HoneyBadgerQuicConfig,
};
use crate::tests::test_utils::{init_crypto_provider, setup_test_tracing};

/// Test: open_share_in_exp on a known value reconstructs correctly.
///
/// Creates n engines in-process, shares a known value (42), then
/// calls `open_share_in_exp` on each engine. Verifies the result
/// equals `G1::generator() * Fr::from(42)`.
#[tokio::test(flavor = "multi_thread")]
async fn test_open_share_in_exp_known_value() {
    init_crypto_provider();
    setup_test_tracing();

    let n = 5;
    let t = 1;
    let instance_id = 700_000;
    let base_port = 11400;
    let ty = ShareType::SecretInt { bit_length: 256 };

    let config = HoneyBadgerQuicConfig {
        mpc_timeout: Duration::from_secs(10),
        connection_retry_delay: Duration::from_millis(100),
        ..Default::default()
    };

    // Create network
    let (mut servers, mut recv) = setup_honeybadger_quic_network::<Fr>(
        n,
        t,
        0,
        0,
        instance_id,
        base_port,
        config.clone(),
        None,
    )
    .await
    .expect("Failed to create servers");

    // Start servers and spawn message processors
    for (i, server) in servers.iter_mut().enumerate() {
        server.start().await.expect("Failed to start server");
        let mut node = server.node.clone();
        let network = server
            .network
            .clone()
            .expect("network should be set after start()");
        let mut rx = recv.remove(0);
        tokio::spawn(async move {
            while let Some((sender_id, raw_msg)) = rx.recv().await {
                match crate::net::open_registry::try_handle_wire_message(sender_id, &raw_msg) {
                    Ok(true) => continue,
                    Err(e) => {
                        tracing::warn!("Node {i} failed to handle open wire message: {e}");
                        continue;
                    }
                    Ok(false) => {}
                }
                match crate::net::hb_engine::try_handle_open_exp_wire_message(sender_id, &raw_msg) {
                    Ok(true) => continue,
                    Err(e) => {
                        tracing::warn!("Node {i} failed to handle open_exp wire message: {e}");
                        continue;
                    }
                    Ok(false) => {}
                }
                if let Err(e) = node.process(sender_id, raw_msg, network.clone()).await {
                    tracing::error!("Node {i} failed to process message: {e:?}");
                }
            }
        });
    }

    // Connect servers
    for server in &servers {
        server
            .connect_to_peers()
            .await
            .expect("Failed to connect to peers");
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Create engines from existing nodes
    let engines: Vec<Arc<HoneyBadgerMpcEngine>> = (0..n)
        .map(|i| {
            HoneyBadgerMpcEngine::<ark_bls12_381::Fr, ark_bls12_381::G1Projective>::from_existing_node(
                instance_id,
                i,
                n,
                t,
                servers[i]
                    .network
                    .clone()
                    .expect("network should be set"),
                servers[i].node.clone(),
            )
        })
        .collect();

    // Share a known value (42) across all parties
    let secret = Fr::from(42u64);
    let mut rng = ark_std::test_rng();
    let all_shares =
        RobustShare::compute_shares(secret, n, t, None, &mut rng).expect("compute_shares failed");

    // Each party's share bytes
    let share_bytes_vec: Vec<Vec<u8>> = all_shares
        .iter()
        .map(|s| {
            let mut buf = Vec::new();
            s.serialize_compressed(&mut buf)
                .expect("serialize share failed");
            buf
        })
        .collect();

    // Serialize the generator
    let generator = G1::generator();
    let mut gen_bytes = Vec::new();
    generator
        .into_affine()
        .serialize_compressed(&mut gen_bytes)
        .expect("serialize generator failed");

    // Expected result: generator * 42
    let expected = generator * secret;
    let mut expected_bytes = Vec::new();
    expected
        .into_affine()
        .serialize_compressed(&mut expected_bytes)
        .expect("serialize expected failed");

    // Call open_share_in_exp on all parties concurrently
    let handles: Vec<_> = (0..n)
        .map(|i| {
            let engine = engines[i].clone();
            let share = share_bytes_vec[i].clone();
            let gen = gen_bytes.clone();
            tokio::spawn(async move { engine.open_share_in_exp(ty, &share, &gen) })
        })
        .collect();

    let results: Vec<Vec<u8>> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.expect("task panicked").expect("open_share_in_exp failed"))
        .collect();

    // All parties should get the same result
    for (i, result) in results.iter().enumerate() {
        assert_eq!(
            result, &expected_bytes,
            "Party {} got different result from expected",
            i
        );
    }

    // Also verify all parties agree
    for i in 1..n {
        assert_eq!(results[0], results[i], "Party 0 and party {} disagree", i);
    }

    tracing::info!(
        "open_share_in_exp: all {} parties agree on correct public point",
        n
    );
}

/// Test: simulated DKG flow — shares of a random secret → open_share_in_exp.
///
/// Simulates what `random_share` would produce: all parties hold shares of the
/// same random secret (generated by `compute_shares`). Then each party calls
/// `open_share_in_exp` with G1::generator(). All parties should get identical,
/// non-trivial public key bytes.
///
/// This avoids needing a real preprocessing network while still testing the
/// full DKG primitive flow (share → open_in_exp → public key).
#[tokio::test(flavor = "multi_thread")]
async fn test_simulated_dkg_flow() {
    init_crypto_provider();
    setup_test_tracing();

    let n = 5;
    let t = 1;
    let instance_id = 700_001;
    let base_port = 11500;
    let ty = ShareType::SecretInt { bit_length: 256 };

    let config = HoneyBadgerQuicConfig {
        mpc_timeout: Duration::from_secs(10),
        connection_retry_delay: Duration::from_millis(100),
        ..Default::default()
    };

    // Create network (no preprocessing needed for this test)
    let (mut servers, mut recv) = setup_honeybadger_quic_network::<Fr>(
        n,
        t,
        0,
        0,
        instance_id,
        base_port,
        config.clone(),
        None,
    )
    .await
    .expect("Failed to create servers");

    // Start servers and spawn message processors
    for (i, server) in servers.iter_mut().enumerate() {
        server.start().await.expect("Failed to start server");
        let mut node = server.node.clone();
        let network = server
            .network
            .clone()
            .expect("network should be set after start()");
        let mut rx = recv.remove(0);
        tokio::spawn(async move {
            while let Some((sender_id, raw_msg)) = rx.recv().await {
                match crate::net::open_registry::try_handle_wire_message(sender_id, &raw_msg) {
                    Ok(true) => continue,
                    Err(e) => {
                        tracing::warn!("Node {i} failed to handle open wire message: {e}");
                        continue;
                    }
                    Ok(false) => {}
                }
                match crate::net::hb_engine::try_handle_open_exp_wire_message(sender_id, &raw_msg) {
                    Ok(true) => continue,
                    Err(e) => {
                        tracing::warn!("Node {i} failed to handle open_exp wire message: {e}");
                        continue;
                    }
                    Ok(false) => {}
                }
                if let Err(e) = node.process(sender_id, raw_msg, network.clone()).await {
                    tracing::error!("Node {i} failed to process message: {e:?}");
                }
            }
        });
    }

    // Connect servers
    for server in &servers {
        server
            .connect_to_peers()
            .await
            .expect("Failed to connect to peers");
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Create engines from existing nodes
    let engines: Vec<Arc<HoneyBadgerMpcEngine>> = (0..n)
        .map(|i| {
            HoneyBadgerMpcEngine::<ark_bls12_381::Fr, ark_bls12_381::G1Projective>::from_existing_node(
                instance_id,
                i,
                n,
                t,
                servers[i]
                    .network
                    .clone()
                    .expect("network should be set"),
                servers[i].node.clone(),
            )
        })
        .collect();

    // Simulate random_share: create shares of a random secret
    let mut rng = ark_std::test_rng();
    let random_secret = Fr::from(ark_std::rand::Rng::gen::<u64>(&mut rng));
    let all_shares = RobustShare::compute_shares(random_secret, n, t, None, &mut rng)
        .expect("compute_shares failed");

    let share_bytes_vec: Vec<Vec<u8>> = all_shares
        .iter()
        .map(|s| {
            let mut buf = Vec::new();
            s.serialize_compressed(&mut buf)
                .expect("serialize share failed");
            buf
        })
        .collect();

    // Verify shares are different
    for i in 1..n {
        assert_ne!(
            share_bytes_vec[0], share_bytes_vec[i],
            "Party 0 and party {} got identical shares",
            i
        );
    }

    // Each party calls open_share_in_exp with G1 generator
    let generator = G1::generator();
    let mut gen_bytes = Vec::new();
    generator
        .into_affine()
        .serialize_compressed(&mut gen_bytes)
        .expect("serialize generator failed");

    // Expected public key: generator * random_secret
    let expected_pk = generator * random_secret;
    let mut expected_pk_bytes = Vec::new();
    expected_pk
        .into_affine()
        .serialize_compressed(&mut expected_pk_bytes)
        .expect("serialize expected pk failed");

    let exp_handles: Vec<_> = (0..n)
        .map(|i| {
            let engine = engines[i].clone();
            let share = share_bytes_vec[i].clone();
            let gen = gen_bytes.clone();
            tokio::spawn(async move { engine.open_share_in_exp(ty, &share, &gen) })
        })
        .collect();

    let pk_results: Vec<Vec<u8>> = futures::future::join_all(exp_handles)
        .await
        .into_iter()
        .map(|r| r.expect("task panicked").expect("open_share_in_exp failed"))
        .collect();

    // All parties should agree on the public key
    for i in 1..n {
        assert_eq!(
            pk_results[0], pk_results[i],
            "Party 0 and party {} disagree on public key",
            i
        );
    }

    // Public key should match expected
    assert_eq!(
        pk_results[0], expected_pk_bytes,
        "Public key doesn't match expected generator * secret"
    );

    // Public key should not be the identity (zero point)
    let identity = G1::default();
    let mut identity_bytes = Vec::new();
    identity
        .into_affine()
        .serialize_compressed(&mut identity_bytes)
        .expect("serialize identity failed");

    assert_ne!(
        pk_results[0], identity_bytes,
        "Public key is the identity (trivial)"
    );

    tracing::info!(
        "Simulated DKG flow: all {} parties agree on correct public key ({} bytes)",
        n,
        pk_results[0].len()
    );
}
