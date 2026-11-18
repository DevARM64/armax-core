//! `armax-pow`: reglas de consenso del PoW de ARMax.
//!
//! * `u256`      — entero de 256 bits para targets y trabajo (solo aritmética entera).
//! * `header`    — cabecera canónica de 124 bytes, id del bloque.
//! * `lwma`      — dificultad LWMA en espacio de targets (T = 300 s, ventana 30).
//! * `consensus` — constantes, límite de PoW, reglas de época.
//! * `validate`  — validación barata primero, PoW después; minero de referencia.

pub mod consensus;
pub mod header;
pub mod lwma;
pub mod u256;
pub mod validate;

pub use header::{BlockHeader, DecodeError, Hash32, HEADER_LEN};
pub use lwma::{next_target, WindowEntry};
pub use u256::{block_work, U256};
pub use validate::{
    median_time_past, meets_target, mine, mine_at, validate_header, validate_header_cheap, verify_pow,
    verify_pow_at, HeaderError, ParentInfo,
};
