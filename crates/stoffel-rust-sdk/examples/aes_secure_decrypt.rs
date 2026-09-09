//! Secure decryption + in-MPC text manipulation over a client-supplied
//! ciphertext, driven by the Rust SDK.
//!
//! The client encrypts the message "hello stoffel vm" under AES-128-CTR and
//! supplies the **ciphertext** as a secret client input (client 0); the key
//! holder supplies the secret AES key (client 1). The MPC nodes recover the
//! plaintext *inside* MPC (CTR is self-inverse, so re-running the keystream
//! against the secret ciphertext decrypts it without revealing it), uppercase
//! its ASCII letters, and deliver the transformed text back to client 0 via
//! `send_to_client`. The plaintext is never opened to the compute nodes.
//!
//! Run:
//!   cargo run --release -p stoffel-rust-sdk --example aes_secure_decrypt
//! (set STOFFEL_RUN_BIN to a built `stoffel-run` if it is not auto-discovered).

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use stoffel::prelude::*;

const PROGRAM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../stoffel-lang/examples/mpc_aes128_secure_decrypt/main.stfl"
);
const KEY: [u8; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];
/// The program's public CTR counter block (`public_block([240..255])`).
const CTR0: [u8; 16] = [
    240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255,
];
const MESSAGE: &[u8; 16] = b"hello stoffel vm";
const EXPECTED: &[u8; 16] = b"HELLO STOFFEL VM";

/// AES-128-CTR encrypt one block: ciphertext = plaintext XOR AES_enc(counter).
fn ctr_encrypt_block(plaintext: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(GenericArray::from_slice(&KEY));
    let mut keystream = GenericArray::clone_from_slice(&CTR0);
    cipher.encrypt_block(&mut keystream);
    let mut ciphertext = [0u8; 16];
    for i in 0..16 {
        ciphertext[i] = plaintext[i] ^ keystream[i];
    }
    ciphertext
}

/// AES feeds each byte as 8 secret bits in little-endian (LSB-first) order.
fn bits_lsb_first(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for b in 0..8 {
            bits.push((byte >> b) & 1 == 1);
        }
    }
    bits
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> stoffel::Result<()> {
    let ciphertext = ctr_encrypt_block(MESSAGE);
    let ciphertext_bits = bits_lsb_first(&ciphertext);
    let key_bits = bits_lsb_first(&KEY);

    println!(
        "Client message      = {:?}",
        std::str::from_utf8(MESSAGE).unwrap()
    );
    println!(
        "Client ciphertext   = {}",
        ciphertext
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    println!("Running AES-128 secure decryption + uppercase over MPC...");
    println!("(client 0 = ciphertext, client 1 = key; plaintext never revealed to nodes)");

    let (_returned, client_outputs) = Stoffel::compile_file(PROGRAM)?
        .optimization_level(3)
        .parties(5)
        .threshold(1)
        // Declaring output clients enables the client-output capability so the
        // program's `send_to_client` path runs. Must cover the full input-client
        // roster (slots 0 and 1).
        .expected_output_clients(2)
        .with_client_input(0, &ciphertext_bits) // data owner: 128 ciphertext bits
        .with_client_input(1, &key_bits) // key holder: 128 key bits
        .execute_local_capturing_client_outputs()
        .await?;

    // What client 0 actually RECEIVES via send_to_client, reconstructed off the
    // output shares — never revealed to the nodes. The SDK decodes each output
    // through the program's client-IO manifest, so the 128 secret bits come back
    // as typed `Value::Bool`s; `bytes()` packs them LSB-first into the 16 bytes.
    let client0 = client_outputs
        .iter()
        .find(|o| o.client_slot == 0)
        .expect("client 0 should receive a client output");
    assert_eq!(
        client0.values.len(),
        128,
        "expected 128 output bits, got {}",
        client0.values.len()
    );
    let received = client0.bytes();
    let received_text = String::from_utf8_lossy(&received);

    println!("client-received text = {received_text:?}");
    println!(
        "expected             = {:?}",
        std::str::from_utf8(EXPECTED).unwrap()
    );
    assert_eq!(
        received.as_slice(),
        EXPECTED.as_slice(),
        "client should receive the decrypted-and-uppercased plaintext"
    );
    println!("PASS: nodes decrypted + transformed the text without ever seeing the plaintext");
    Ok(())
}
