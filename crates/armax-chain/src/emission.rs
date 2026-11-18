//! Calendario de emisión: sin premine, todo sale de bloques minados.
//!
//! Parámetros (decididos): recompensa inicial 25 ARM, bloques de 300 s, suministro máximo
//! nominal 21,000,000 ARM. Con reducciones a la mitad, esos tres valores fijan la longitud
//! de la era: `25 × ERA × 2 = 21,000,000  →  ERA = 420,000 bloques` (3.99 años a 300 s).
//!
//! El génesis (altura 0) no emite nada. La era `e` cubre las alturas
//! `[e·ERA + 1, (e+1)·ERA]` y paga `INITIAL_SUBSIDY >> e`.
//!
//! Por el redondeo a unidades enteras el total emitido queda 0.0462 ARM por debajo de
//! 21,000,000 (ver test `max_supply_matches_independent_calculation`). Además, lo que el
//! amortiguador de recompensa recorta **no se emite**, así que el suministro real
//! será menor: 21M es una cota superior, no una promesa de emisión.

use crate::types::COIN;

pub const INITIAL_SUBSIDY: u64 = 25 * COIN;
pub const HALVING_INTERVAL: u64 = 420_000;
pub const NOMINAL_MAX_SUPPLY: u64 = 21_000_000 * COIN;

/// Recompensa base (antes del amortiguador) del bloque de altura `height`.
pub const fn subsidy(height: u64) -> u64 {
    if height == 0 {
        return 0;
    }
    let era = (height - 1) / HALVING_INTERVAL;
    if era >= 64 {
        0
    } else {
        INITIAL_SUBSIDY >> era
    }
}

/// Suma exacta de todas las recompensas base de la historia, en unidades.
pub const fn max_supply() -> u64 {
    let mut total = 0u64;
    let mut era = 0u64;
    while era < 64 {
        total += HALVING_INTERVAL * (INITIAL_SUBSIDY >> era);
        era += 1;
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_emits_nothing_first_block_pays_full() {
        assert_eq!(subsidy(0), 0);
        assert_eq!(subsidy(1), 25 * COIN);
    }

    #[test]
    fn halving_boundaries() {
        assert_eq!(subsidy(HALVING_INTERVAL), 25 * COIN); // último bloque de la era 0
        assert_eq!(subsidy(HALVING_INTERVAL + 1), 25 * COIN / 2);
        assert_eq!(subsidy(2 * HALVING_INTERVAL), 25 * COIN / 2);
        assert_eq!(subsidy(2 * HALVING_INTERVAL + 1), 25 * COIN / 4);
    }

    #[test]
    fn eventually_zero_and_never_increases() {
        let mut prev = u64::MAX;
        for era in 0..70u64 {
            let s = subsidy(era * HALVING_INTERVAL + 1);
            assert!(s <= prev);
            prev = s;
        }
        assert_eq!(subsidy(40 * HALVING_INTERVAL), 0);
        assert_eq!(subsidy(u64::MAX), 0);
    }

    #[test]
    fn max_supply_matches_independent_calculation() {
        // Valor calculado aparte con Python: 420000 · Σ_k (2.5e9 >> k) para k = 0..63.
        assert_eq!(max_supply(), 2_099_999_995_380_000);
        assert!(max_supply() <= NOMINAL_MAX_SUPPLY);
        // diferencia por redondeo: 0.0462 ARM
        assert_eq!(NOMINAL_MAX_SUPPLY - max_supply(), 4_620_000);
    }

    #[test]
    fn era_lasts_about_four_years_at_the_target_block_time() {
        // la reducción a la mitad debe caer cada ~4 años (3.99) con el tiempo de bloque de consenso
        let secs = HALVING_INTERVAL * armax_pow::consensus::TARGET_BLOCK_TIME;
        let years = secs as f64 / (365.25 * 86_400.0);
        assert!((3.9..=4.1).contains(&years), "{years}");
    }

    #[test]
    fn half_of_supply_in_first_era() {
        let first_era = HALVING_INTERVAL * subsidy(1);
        assert_eq!(first_era, 10_500_000 * COIN);
    }
}
