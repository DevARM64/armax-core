//! `armax-keys`: llaves, direcciones y transacciones de ARMax. **Sin dependencias externas**
//! (solo `armax-vm` para SHA-256 y `armax-chain` para el tipo `Address`).
//!
//! * `sha512`   — SHA-512, HMAC y PBKDF2.
//! * `ed25519`  — firmas Ed25519 (RFC 8032) con verificación estricta de consenso.
//! * `bip39`    — frase mnemónica de 12/24 palabras y semilla.
//! * `slip10`   — derivación jerárquica Ed25519 (`m/44'/ARMX'/cuenta'/0'/índice'`).
//! * `address`  — dirección = hash de la clave pública; texto Bech32m `arm1…`.
//! * `tx`       — transacciones UTXO con firma por entrada.
//! * `utxo`     — conjunto de salidas gastables: doble gasto, dueño, madurez, comisión, reversión.
//! * `wallet`   — cartera con la entropía sellada por una `SecretVault` (Android Keystore).
//! * `x25519`  — acuerdo de claves Diffie-Hellman (RFC 7748).
//! * `aead`    — ChaCha20-Poly1305 (RFC 8439).
//! * `kdf`     — HMAC-SHA256 y HKDF (RFC 5869).
//! * `rng`      — entropía del sistema operativo (pruebas y herramientas).
//!
//! Todo el código se verificó contra vectores oficiales (RFC 8032, FIPS 180-4, BIP-39, BIP-350,
//! SLIP-0010) y contra implementaciones de referencia independientes (`tests/reference_vectors.rs`).

pub mod address;
pub mod aead;
pub mod bip39;
pub mod ed25519;
pub mod kdf;
pub mod rng;
pub mod sha512;
pub mod slip10;
pub mod tx;
pub mod utxo;
pub mod x25519;
pub mod wallet;
