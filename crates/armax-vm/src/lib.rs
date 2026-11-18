//! `armax-vm`: VM de prueba de trabajo de ARMax.
//!
//! * `aes`    — rondas AES (portable + backend ARM64 con intrínsecos).
//! * `sha256` — hash para semillas y digest final (sin dependencias).
//! * `isa`    — 160 instrucciones y mutación de la tabla por época.
//! * `gen`    — generador AES secuencial (scratchpad, programa, registros).
//! * `vm`     — intérprete y `pow_hash`.
//! * `mem`    — scratchpad con reserva fallible y comprobación de `MemAvailable`.

pub mod aes;
pub mod gen;
pub mod isa;
pub mod mem;
pub mod sha256;
pub mod vm;

pub use aes::{native_aes_available, Aes, Native, Portable};
pub use isa::{OpTable, NUM_OPS};
pub use mem::{check_memory, MemError, Scratchpad};
pub use vm::{pow_hash, Params};
