//! `armax-chain`: emisión, coinbase, amortiguador por dirección y elección de cadena.
//!
//! * `types`    — `Address`, `COIN`.
//! * `emission` — subsidio por altura (25 ARM, era de 420,000 bloques, tope nominal de 21M).
//! * `merkle`   — raíz de Merkle sin mutabilidad.
//! * `block`    — coinbase (hasta 64 salidas con partes en ppm), bloque y génesis (sin premine).
//! * `damper`   — amortiguador del tope de 40 H/s por dirección.
//! * `pow_check`— verificación del PoW desacoplada (`VmPow` real, `SkipPow` para tests).
//! * `chain`    — índice de bloques, validación completa, trabajo acumulado y reorganizaciones.

pub mod block;
pub mod chain;
pub mod damper;
pub mod emission;
pub mod merkle;
pub mod pow_check;
pub mod types;

pub use block::{genesis_block, Block, Coinbase, Output, MAX_COINBASE_OUTPUTS, MIN_SHARE_PPM, SHARE_TOTAL};
pub use chain::{check_shares, AddOutcome, Chain, ChainError, HeaderRun, HeaderValidator};
pub use damper::DamperParams;
pub use pow_check::{FullPow, PowCheck, SharePowCheck, SkipPow, VmPow};
pub use types::{Address, COIN};
