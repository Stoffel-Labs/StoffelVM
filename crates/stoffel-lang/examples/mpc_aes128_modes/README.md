# AES-128 CTR & CBC modes over MPC (threshold key, client secret input)

Builds proper modes of operation on top of the single-block AES-128 cipher
(`aes128_encrypt` / `aes128_decrypt` from
[`mpc_aes128_threshold_input`](../mpc_aes128_threshold_input)). A 2-block secret
plaintext is supplied by a client; the AES key is a secret-shared **threshold
key**; the IV / initial counter block are public. Verified against the official
**NIST SP 800-38A** AES-128 test vectors.

| Input | Source | Visibility |
|-------|--------|------------|
| Plaintext (2 × 128 bits) | client slot 0 | secret-shared |
| Key (128 bits) | client slot 1 | threshold key, secret-shared |
| IV / initial counter block | built in `main` | public |
| Ciphertext / recovered plaintext | revealed | public |

## Modes

- **CTR** (`ctr_crypt`): `keystream_i = AES_enc(counter_i, key)`, `out_i = data_i ⊕ keystream_i`.
  Encryption and decryption are the *same* operation. The initial counter is
  public, and later counter blocks are derived by incrementing it as a 128-bit
  big-endian integer.
- **CBC** (`cbc_encrypt` / `cbc_decrypt`): `C_i = AES_enc(P_i ⊕ C_{i-1}, key)`
  with `C_{-1} = IV`; decryption is `P_i = AES_dec(C_i, key) ⊕ C_{i-1}`.

Block XOR (`bytes_xor`) is linear, so the modes add **no** extra multiplication
rounds beyond the underlying AES block calls.

## Running it

```bash
cargo build --release -p stoffel-vm-runner --bin stoffel-run -p stoffel --bin stoffel
./run.sh
```

`run.sh` feeds the NIST plaintext (slot 0) and key (slot 1) as secret bits and
runs the 5-party local simulator. The program prints **8 decimal byte-lists** in
this order; the primed values are decrypted plaintext and must equal P0/P1:

```
NIST SP 800-38A (Key = 2b7e151628aed2a6abf7158809cf4f3c)
P0  = 6bc1bee22e409f96e93d7e117393172a  P1 = ae2d8a571e03ac9c9eb76fac45af8e51

1 CTR  C0 = [135,77,97,145,182,32,227,38,27,239,104,100,153,13,182,206]
2 CTR  C1 = [152,6,246,107,121,112,253,255,134,23,24,123,185,255,253,255]
3 CTR  P0'= [107,193,190,226,46,64,159,150,233,61,126,17,115,147,23,42]   (= P0)
4 CTR  P1'= [174,45,138,87,30,3,172,156,158,183,111,172,69,175,142,81]    (= P1)
5 CBC  C0 = [118,73,171,172,129,25,178,70,206,233,142,155,18,233,25,125]
6 CBC  C1 = [80,134,203,155,80,114,25,238,149,219,17,58,145,118,120,178]
7 CBC  P0'= [107,193,190,226,46,64,159,150,233,61,126,17,115,147,23,42]   (= P0)
8 CBC  P1'= [174,45,138,87,30,3,172,156,158,183,111,172,69,175,142,81]    (= P1)
```

- CTR C0,C1  = NIST CTR ciphertext `874d6191…b6ce`, `9806f66b…fdff`.
- CBC C0,C1  = NIST CBC ciphertext `7649abac…197d`, `5086cb9b…78b2`.

Change `PLAINTEXT_HEX` / `KEY_HEX` (and, for CTR/CBC, the public IV / initial
counter in `main`) to process your own data.

## Notes

- ECB is intentionally **not** provided: encrypting blocks independently under a
  block cipher leaks equality of plaintext blocks. CTR and CBC use a public
  IV/counter so identical plaintext blocks encrypt differently.
- CTR is the cheapest mode here in MPC: the keystream depends only on the public
  counter sequence and the key, so it can be precomputed; the per-block data
  step is just a free XOR.
