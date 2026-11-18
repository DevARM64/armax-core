//! Constantes de consenso y reglas de época.
//!
//! Todos los valores marcados PROVISIONAL deben revisarse con mediciones de red real
//! antes del génesis: cambiarlos después es un hard fork.

use armax_vm::sha256::sha256;
use armax_vm::OpTable;

use crate::u256::U256;

/// Tiempo de bloque objetivo, en segundos (decidido: 300 s). Con 25 ARM por bloque y un
/// suministro de 21M, la era de 420,000 bloques dura 3.99 años: la reducción a la mitad
/// cae cada ~4 años.
pub const TARGET_BLOCK_TIME: u64 = 300;

/// Ventana de LWMA en bloques (30 bloques = 2.5 h a 300 s). Elegida con `examples/lwma_sweep.rs`:
/// con el ciclo diurno de teléfonos (4x de oscilación) una ventana corta sigue mejor el
/// hashrate que una de 60 bloques (dispersión 1.18 frente a 1.27). PROVISIONAL.
pub const LWMA_WINDOW: usize = 30;

/// Los tiempos de solución se acotan a ±6·T para limitar el efecto de timestamps manipulados.
pub const LWMA_SOLVETIME_CLAMP: i64 = 6;

/// Ventana de la mediana de tiempo (MTP): un bloque debe ser posterior a la mediana de los últimos 11.
pub const MTP_WINDOW: usize = 11;

/// Un timestamp no puede superar el reloj local en más de esto (s). PROVISIONAL.
pub const MAX_FUTURE_SECS: u64 = 600;

/// Versión de cabecera actual.
pub const HEADER_VERSION: u32 = 1;

/// Dificultad inicial ≈ un teléfono (~5 H/s × 300 s). PROVISIONAL.
pub const INITIAL_DIFFICULTY: u64 = 1500;

/// Longitud de época en bloques (1024 bloques ≈ 3.6 días a 300 s). PROVISIONAL.
pub const EPOCH_LENGTH: u64 = 1024;

/// La semilla de la época `e ≥ 1` es el id del bloque de altura `e·EPOCH_LENGTH − EPOCH_LAG`:
/// los mineros la conocen con antelación y no hay carrera con el primer bloque de la época.
pub const EPOCH_LAG: u64 = 64;

/// Target máximo (dificultad mínima 2). Ningún bloque puede declarar un target mayor.
pub fn pow_limit() -> U256 {
    U256::pow2(255).unwrap()
}

/// Target del génesis: `⌊(2^256 − 1) / INITIAL_DIFFICULTY⌋`.
pub fn initial_target() -> U256 {
    U256::MAX.div_u64(INITIAL_DIFFICULTY)
}

pub fn epoch_of(height: u64) -> u64 {
    height / EPOCH_LENGTH
}

/// Altura del bloque cuyo id siembra la época `epoch`. `None` para la época 0 (semilla fija).
pub fn epoch_seed_height(epoch: u64) -> Option<u64> {
    if epoch == 0 {
        None
    } else {
        Some(epoch * EPOCH_LENGTH - EPOCH_LAG)
    }
}

/// Semilla de la época 0.
pub fn genesis_epoch_seed() -> [u8; 32] {
    sha256(b"ARMAX genesis epoch seed v0")
}

/// Tabla de opcodes de una época a partir de su semilla.
pub fn op_table_for_seed(seed: &[u8; 32]) -> OpTable {
    OpTable::for_epoch(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_math() {
        assert_eq!(epoch_of(0), 0);
        assert_eq!(epoch_of(EPOCH_LENGTH - 1), 0);
        assert_eq!(epoch_of(EPOCH_LENGTH), 1);
        assert_eq!(epoch_seed_height(0), None);
        for e in 1..50u64 {
            let h = epoch_seed_height(e).unwrap();
            // la semilla se conoce antes de que empiece la época
            assert!(h < e * EPOCH_LENGTH);
            // y pertenece a la época anterior (no a la propia)
            assert_eq!(epoch_of(h), e - 1);
        }
    }

    #[test]
    fn constants_are_sane() {
        assert!(EPOCH_LAG < EPOCH_LENGTH);
        assert!(initial_target() < pow_limit());
        assert!(!initial_target().is_zero());
        assert!(LWMA_WINDOW >= MTP_WINDOW);
    }

    #[test]
    fn epoch_tables_differ() {
        let a = op_table_for_seed(&genesis_epoch_seed());
        let b = op_table_for_seed(&[1u8; 32]);
        assert_ne!(a.permutation(), b.permutation());
    }
}
