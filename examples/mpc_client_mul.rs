// Example: Client-provided secret inputs and secret multiplication (no network)
// Run with: cargo run -p stoffel-vm --example mpc_client_mul


use ark_bls12_381::Fr;
use ark_ff::FftField;
use ark_std::test_rng;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;

// Configuration
const N: usize = 5;      // number of servers
const T: usize = 1;      // threshold (t), requires 2t+1=3 shares to reconstruct

fn main() {
    // Client inputs
    let a_val: u64 = 42;
    let b_val: u64 = 37;

    // Client: generate shares for a and b
    let mut rng = test_rng();
    let a = Fr::from(a_val);
    let b = Fr::from(b_val);

    let shares_a = RobustShare::compute_shares(a, N, T, None, &mut rng)
        .expect("failed to compute shares for a");
    let shares_b = RobustShare::compute_shares(b, N, T, None, &mut rng)
        .expect("failed to compute shares for b");

    // Servers: receive their shares from client and compute local product shares.
    // Note: multiplying Shamir shares doubles the polynomial degree (<= 2T).
    // We'll reconstruct using 2T+1 shares (which is 3 for T=1).
    let mut product_shares: Vec<RobustShare<Fr>> = Vec::with_capacity(N);
    for i in 0..N {
        let sa = &shares_a[i];
        let sb = &shares_b[i];
        let prod = sa.share[0] * sb.share[0];
        // degree after multiplication can be up to 2T
        let deg = sa.degree.max(sb.degree) * 2;
        product_shares.push(RobustShare::new(prod, sa.id, deg));
    }

    // Reconstruct from any 2T+1 shares (take first 3)
    let subset = &product_shares[0..(2 * T + 1)];
    let (_, result) = RobustShare::recover_secret(subset, N).expect("reconstruction failed");

    let expected = Fr::from(a_val * b_val);
    assert_eq!(result, expected, "secret multiplication mismatch");

    println!(
        "✅ Client-provided secret inputs: {} × {} = {}",
        a_val,
        b_val,
        result.into_bigint().0[0]
    );
}
