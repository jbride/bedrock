//! # HHD Sphincs+ and secp256k1 Example
//!
//! Demonstrates how a single BIP-39 mnemonic can deterministically produce
//! both a classical (secp256k1 Schnorr) and a post-quantum (SLH-DSA-128s)
//! keypair via BIP-85, with full cryptographic separation between them.
//!
//! ## Derivation flow
//!
//! ```text
//! BIP-39 mnemonic
//!   ├── BIP-85 m/83696968'/83286642'/1'  →  secp256k1 Schnorr keypair
//!   └── BIP-85 m/83696968'/83286642'/7'  →  SLH-DSA-128s (SPHINCS+) keypair
//! ```
//!
//! ## Entropy budget per scheme
//!
//! BIP-85 always outputs 64 bytes (512 bits) via HMAC-SHA512.  Each scheme
//! consumes a different slice of that output:
//!
//! ```text
//! Scheme          BIP-85 output   Bytes consumed   Bytes discarded   Actual entropy
//! ─────────────────────────────────────────────────────────────────────────────────
//! secp256k1       64 B (512 bit)  32 B [0..32]     32 B [32..64]     256 bits
//! SLH-DSA-128s    64 B (512 bit)  32 B [0..32] *   32 B [32..64]     256 bits
//! ```
//!
//! \* For SLH-DSA-128s the 32 consumed bytes seed a ChaCha20 CSPRNG that
//!   expands them to the 128 bytes required by the `bitcoinpqc` API.
//!   The expansion is deterministic; no additional entropy is introduced.
//!   FIPS 205 SLH-DSA-128s (n=16) only requires 3×16 = 48 bytes of true
//!   randomness, so 256 bits of seed entropy is more than sufficient.
//!
//! Running with the same mnemonic always produces the same keypairs.

#![allow(missing_docs)]

use bitcoinpqc::{generate_keypair, sign, verify, Algorithm};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use tectonic_bedrock::hhd::{Bip85, Mnemonic, SignatureScheme};

fn main() {
    println!("HHD Multi-Algorithm Key Derivation Example");
    println!("===========================================");
    println!("secp256k1 Schnorr + SLH-DSA-128s (SPHINCS+) from a single mnemonic\n");

    // -----------------------------------------------------------------------
    // 1. Shared BIP-39 mnemonic — the single backup phrase for both keys
    // -----------------------------------------------------------------------
    let phrase =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = Mnemonic::from_phrase(phrase).expect("valid BIP-39 phrase");

    println!("Mnemonic: {phrase}");
    println!(
        "BIP-85 path (secp256k1):   {}",
        Bip85::derivation_path_from_scheme(SignatureScheme::EcdsaSecp256k1)
    );
    println!(
        "BIP-85 path (SLH-DSA-128s): {}",
        Bip85::derivation_path_from_scheme(SignatureScheme::SlhDsa128s)
    );
    println!();

    let message = b"Hello from a hybrid BIP-85 wallet!";

    // -----------------------------------------------------------------------
    // 2. secp256k1 Schnorr keypair
    //
    //    Entropy: BIP-85 → 64 bytes (512 bits)
    //             bytes [0..32] (256 bits) → private key
    //             bytes [32..64]           → discarded
    //
    //    The bitcoinpqc SECP256K1_SCHNORR convention uses the 32-byte value
    //    directly as the private scalar.  Schnorr sign/verify operates on a
    //    32-byte SHA-256 message hash.
    // -----------------------------------------------------------------------
    println!("--- secp256k1 Schnorr ---");

    let ec_seed =
        Bip85::derive_seed_from_mnemonic(mnemonic.clone(), SignatureScheme::EcdsaSecp256k1, None)
            .expect("BIP-85 secp256k1 derivation failed");

    let ec_seed_bytes = ec_seed.as_seed().as_bytes();
    println!("BIP-85 output  (64 B / 512 bit): {}", hex(ec_seed_bytes));
    println!("Entropy used   (32 B / 256 bit): {}", hex(&ec_seed_bytes[..32]));
    println!("Discarded      (32 B / 256 bit): {}", hex(&ec_seed_bytes[32..]));

    let ec_keypair =
        generate_keypair(Algorithm::SECP256K1_SCHNORR, &ec_seed_bytes[..32])
            .expect("secp256k1 key generation failed");

    println!("Public key:  {} bytes", ec_keypair.public_key.bytes.len());
    println!("Secret key:  {} bytes", ec_keypair.secret_key.bytes.len());

    let msg_hash = Sha256::digest(message);
    let ec_sig = sign(&ec_keypair.secret_key, &msg_hash).expect("secp256k1 signing failed");
    println!("Signature:   {} bytes", ec_sig.bytes.len());

    match verify(&ec_keypair.public_key, &msg_hash, &ec_sig) {
        Ok(()) => println!("Verification: OK"),
        Err(e) => println!("Verification: FAILED ({e})"),
    }

    let modified_hash = Sha256::digest(b"Hello from a hybrid BIP-85 wallet! (modified)");
    match verify(&ec_keypair.public_key, &modified_hash, &ec_sig) {
        Ok(()) => println!("ERROR: accepted modified message"),
        Err(_) => println!("Correctly rejected modified message"),
    }
    println!();

    // -----------------------------------------------------------------------
    // 3. SLH-DSA-128s (SPHINCS+) keypair
    //
    //    Entropy: BIP-85 → 64 bytes (512 bits)
    //             bytes [0..32] (256 bits) → ChaCha20 seed
    //             bytes [32..64]           → discarded
    //             ChaCha20 expansion       → 128 bytes passed to bitcoinpqc
    //
    //    The bitcoinpqc API requires >= 128 bytes of input.  FIPS 205
    //    SLH-DSA-128s (n=16) internally needs only 3×n = 48 bytes of true
    //    randomness (SK.seed || SK.prf || PK.seed).  The ChaCha20 expansion
    //    is deterministic: no entropy is added beyond the 256-bit seed.
    // -----------------------------------------------------------------------
    println!("--- SLH-DSA-128s (SPHINCS+) ---");

    let slh_seed =
        Bip85::derive_seed_from_mnemonic(mnemonic.clone(), SignatureScheme::SlhDsa128s, None)
            .expect("BIP-85 SLH-DSA derivation failed");

    let slh_seed_bytes = slh_seed.as_seed().as_bytes();
    println!("BIP-85 output  (64 B / 512 bit): {}", hex(slh_seed_bytes));
    println!("ChaCha20 seed  (32 B / 256 bit): {}", hex(&slh_seed_bytes[..32]));
    println!("Discarded      (32 B / 256 bit): {}", hex(&slh_seed_bytes[32..]));

    let slh_random = expand_seed_to_128(slh_seed_bytes);
    println!("ChaCha20 out  (128 B / 1024 bit): {}", hex(&slh_random));

    let slh_keypair = generate_keypair(Algorithm::SLH_DSA_128S, &slh_random)
        .expect("SLH-DSA-128s key generation failed");

    println!("Public key:  {} bytes", slh_keypair.public_key.bytes.len());
    println!("Secret key:  {} bytes", slh_keypair.secret_key.bytes.len());

    let slh_sig = sign(&slh_keypair.secret_key, message).expect("SLH-DSA signing failed");
    println!("Signature:   {} bytes", slh_sig.bytes.len());

    match verify(&slh_keypair.public_key, message, &slh_sig) {
        Ok(()) => println!("Verification: OK"),
        Err(e) => println!("Verification: FAILED ({e})"),
    }

    let modified = b"Hello from a hybrid BIP-85 wallet! (modified)";
    match verify(&slh_keypair.public_key, modified, &slh_sig) {
        Ok(()) => println!("ERROR: accepted modified message"),
        Err(_) => println!("Correctly rejected modified message"),
    }
    println!();

    // -----------------------------------------------------------------------
    // 4. Determinism: same mnemonic always reproduces both keypairs
    // -----------------------------------------------------------------------
    println!("--- Determinism check ---");

    let ec_seed2 =
        Bip85::derive_seed_from_mnemonic(mnemonic.clone(), SignatureScheme::EcdsaSecp256k1, None)
            .expect("BIP-85 derivation failed");
    let ec_kp2 =
        generate_keypair(Algorithm::SECP256K1_SCHNORR, &ec_seed2.as_seed().as_bytes()[..32])
            .expect("key generation failed");

    let slh_seed2 =
        Bip85::derive_seed_from_mnemonic(mnemonic, SignatureScheme::SlhDsa128s, None)
            .expect("BIP-85 derivation failed");
    let slh_kp2 = generate_keypair(Algorithm::SLH_DSA_128S, &expand_seed_to_128(slh_seed2.as_seed().as_bytes()))
        .expect("key generation failed");

    if ec_keypair.public_key.bytes == ec_kp2.public_key.bytes {
        println!("secp256k1:    same mnemonic → identical keypair: OK");
    } else {
        println!("secp256k1:    ERROR — keypairs differ");
    }

    if slh_keypair.public_key.bytes == slh_kp2.public_key.bytes {
        println!("SLH-DSA-128s: same mnemonic → identical keypair: OK");
    } else {
        println!("SLH-DSA-128s: ERROR — keypairs differ");
    }
}

/// Formats a byte slice as a lowercase hex string.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Expands a 64-byte BIP-85 seed to 128 bytes using a seeded ChaCha20 CSPRNG.
///
/// Only the first 32 bytes (256 bits) of `seed` are used as the ChaCha20 key;
/// the remaining 32 bytes are not consumed.  The 128-byte output is fully
/// determined by those 32 bytes — no additional entropy is introduced.
fn expand_seed_to_128(seed: &[u8]) -> [u8; 128] {
    let mut rng_seed = [0u8; 32];
    rng_seed.copy_from_slice(&seed[..32]);
    let mut rng = ChaCha20Rng::from_seed(rng_seed);
    let mut out = [0u8; 128];
    rng.fill_bytes(&mut out);
    out
}
