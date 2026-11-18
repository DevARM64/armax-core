//! Amortiguador de recompensa por dirección (soft cap de 40 H/s).
//!
//! El consenso no puede medir H/s directamente: solo ve cuántos bloques halló cada dirección.
//! Cada bloque representa `work` hashes esperados, y `work = 2^256/(target+1)`. Una dirección
//! que sostiene `C` H/s durante una ventana de `W` bloques de `T` segundos acumula en
//! promedio `C·W·T` hashes, es decir, `C·W·T / work` bloques. Ese es el número de bloques
//! que se le permiten cobrar completos:
//!
//! ```text
//!   presupuesto = W · T · C                                  (hashes)
//!   n_esperado  = ⌊presupuesto / work⌋                       (bloques)
//!   permitidos  = max(1, n_esperado + Z·⌊√n_esperado⌋)       (margen de Z desviaciones)
//! ```
//!
//! Si la dirección ya halló `c` bloques en la ventana (contando el actual) y `c > permitidos`,
//! el bloque cobra `base · permitidos / c`. En régimen estable `c ≈ s·W`, de modo que la dirección
//! cobra en total ≈ `permitidos` bloques completos por ventana, por mucho hashrate que tenga.
//! **El exceso no se emite** (no se reasigna a nadie), por eso el suministro real queda por
//! debajo del máximo nominal.
//!
//! # Coinbase con varias salidas
//! Cada dirección acumula su **parte** de los bloques de la ventana (en ppm; un bloque entero =
//! 1,000,000) y se le recorta su monto bruto en la misma proporción si supera `permitidos`
//! (`damped_amount`). Los miembros de un pool descentralizado cobran cada uno una fracción pequeña
//! y quedan lejos del tope aunque el pool entero lo supere; una sola dirección con el mismo
//! hashrate sí se recorta. Con una salida del 100 % coincide exactamente con `damped_reward`.
//!
//! # Límites que hay que tener presentes
//! * No frena a quien reparte su hashrate entre muchas direcciones (Sybil): una dirección no
//!   cuesta nada. Es un amortiguador económico, no una garantía criptográfica.
//! * Usa el `work` del bloque actual como estimación del hashrate de la red; con ciclos diarios
//!   de hasta 4x el cap efectivo oscila en ese rango durante el día.
//! * Con una red muy grande `n_esperado` es < 1 y el margen estadístico deja de discriminar:
//!   el mínimo de 1 evita penalizar a un minero pequeño que cobra su primer bloque. Consecuencia:
//!   el tope es fiel a `cap_hps` solo mientras la red total sea menor que `window·cap_hps`
//!   (864·40 = 34,560 H/s, ~7,000 teléfonos); más allá, el tope efectivo es ≈ red/`window`.

use armax_pow::consensus::TARGET_BLOCK_TIME;
use armax_pow::U256;

/// Parámetros de la ventana y del tope. `MAINNET` son valores PROVISIONALES.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DamperParams {
    /// Bloques en la ventana (864 × 300 s = 3 días).
    pub window: usize,
    /// Tope de hashrate por dirección, en H/s.
    pub cap_hps: u64,
    /// Desviaciones estándar de margen para no castigar la varianza.
    pub z: u64,
}

impl DamperParams {
    /// `cap_hps = 40`: unos 8 teléfonos a 1 hilo (~4.6-5.5 H/s) o 4 a 2 hilos (~9 H/s). Medido en un
    /// teléfono real; deja holgura a quien tenga 1-3 teléfonos y frena a quien acumule decenas.
    pub const MAINNET: DamperParams = DamperParams { window: 864, cap_hps: 40, z: 3 };
}

/// Raíz cuadrada entera (⌊√n⌋), exacta para todo `u64`.
pub fn isqrt(n: u64) -> u64 {
    if n < 2 {
        return n;
    }
    let mut lo = 0u64;
    let mut hi = (1u64 << 32) - 1;
    while lo < hi {
        let mid = lo + (hi - lo + 1) / 2;
        if (mid as u128) * (mid as u128) <= n as u128 {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo
}

/// Bloques que una dirección puede cobrar completos en la ventana, dado el `work` del bloque.
pub fn allowed_blocks(work: &U256, p: &DamperParams) -> u64 {
    let budget = (p.window as u64)
        .saturating_mul(TARGET_BLOCK_TIME)
        .saturating_mul(p.cap_hps);
    let expected = if work.0[1] != 0 || work.0[2] != 0 || work.0[3] != 0 || work.0[0] == 0 {
        0 // work no cabe en u64 (> presupuesto) -> 0 bloques esperados
    } else {
        budget / work.0[0]
    };
    expected
        .saturating_add(p.z.saturating_mul(isqrt(expected)))
        .max(1)
}

/// Recompensa final: completa si `count <= allowed`; si no, proporcional.
pub fn damped_reward(base: u64, count: u64, allowed: u64) -> u64 {
    debug_assert!(count >= 1 && allowed >= 1);
    if count <= allowed {
        base
    } else {
        ((base as u128 * allowed as u128) / count as u128) as u64
    }
}

/// Versión proporcional para coinbase con varias salidas. Cada dirección acumula su parte de
/// los bloques de la ventana en partes por millón (`count_ppm`: un bloque entero = 1,000,000,
/// contando el actual). Si supera `allowed` bloques, su parte bruta (`gross`) se recorta en
/// proporción `allowed / count`. Con una sola salida del 100 % es idéntica a `damped_reward`.
pub fn damped_amount(gross: u64, count_ppm: u64, allowed: u64) -> u64 {
    debug_assert!(count_ppm >= 1 && allowed >= 1);
    let allowed_ppm = allowed.saturating_mul(1_000_000);
    if count_ppm <= allowed_ppm {
        gross
    } else {
        ((gross as u128 * allowed_ppm as u128) / count_ppm as u128) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proportional_amount_matches_whole_block_rule() {
        // con partes de bloque entero coincide exactamente con damped_reward
        for base in [1_000u64, 2_500_000_000, 1_234_567_891] {
            for allowed in [1u64, 4, 10] {
                for count in 1..60u64 {
                    assert_eq!(
                        damped_amount(base, count * 1_000_000, allowed),
                        damped_reward(base, count, allowed),
                        "base={base} allowed={allowed} count={count}"
                    );
                }
            }
        }
    }

    #[test]
    fn small_shares_stay_under_the_cap() {
        // un miembro de un pool con 0.5 % de cada bloque en una ventana de 864 bloques
        // acumula 4.32 bloques; con allowed = 10 no se le recorta nada
        assert_eq!(damped_amount(777, 864 * 5_000, 10), 777);
        // quien llegara a 20 bloques con allowed = 10 cobra la mitad
        assert_eq!(damped_amount(1000, 20_000_000, 10), 500);
    }

    #[test]
    fn isqrt_is_exact() {
        for n in 0..10_000u64 {
            let r = isqrt(n);
            assert!(r * r <= n && (r + 1) * (r + 1) > n, "n={n}");
        }
        // incluye cuadrados perfectos y sus vecinos en el borde de u64
        for n in [u64::MAX, u64::MAX - 1, 1 << 62, 4_294_967_295u64 * 4_294_967_295, 4_294_967_295u64 * 4_294_967_295 - 1] {
            let r = isqrt(n) as u128;
            assert!(r * r <= n as u128 && (r + 1) * (r + 1) > n as u128, "n={n}");
        }
        assert_eq!(isqrt(u64::MAX), 4_294_967_295);
    }

    #[test]
    fn full_reward_up_to_allowed_then_proportional() {
        assert_eq!(damped_reward(1000, 1, 4), 1000);
        assert_eq!(damped_reward(1000, 4, 4), 1000);
        assert_eq!(damped_reward(1000, 5, 4), 800);
        assert_eq!(damped_reward(1000, 8, 4), 500);
        assert_eq!(damped_reward(1000, 400, 4), 10);
    }

    #[test]
    fn steady_state_total_is_capped() {
        // Una dirección con 5x el cap en una ventana de W bloques cobra ~`allowed` bloques completos.
        let (base, allowed, w) = (1_000_000u64, 10u64, 100u64);
        let c = 50; // en régimen estable cuenta ≈ s·W
        let total: u64 = (0..w / 2).map(|_| damped_reward(base, c, allowed)).sum();
        assert_eq!(total, (w / 2) * (base * allowed / c));
        assert!(total <= allowed * base * 5 / 5 + base); // ≈ allowed·base
    }

    #[test]
    fn small_network_never_damps() {
        // work = 1500 (≈ un teléfono): presupuesto/1500 = 691,200 bloques >> ventana de 864.
        let a = allowed_blocks(&U256::from_u64(1500), &DamperParams::MAINNET);
        assert!(a > DamperParams::MAINNET.window as u64);
    }

    #[test]
    fn huge_work_still_allows_one_block() {
        let work = U256::pow2(200).unwrap();
        assert_eq!(allowed_blocks(&work, &DamperParams::MAINNET), 1);
        assert_eq!(allowed_blocks(&U256::ZERO, &DamperParams::MAINNET), 1);
    }

    #[test]
    fn allowed_matches_hand_calculation() {
        // presupuesto = 864·300·40 = 10,368,000 ; work = 100,000 -> n = 103 ; √ = 10 ; +3·10
        let a = allowed_blocks(&U256::from_u64(100_000), &DamperParams::MAINNET);
        assert_eq!(a, 103 + 3 * 10);
        // work = 1,000 -> n = 10,368 ; √ = 101
        let a = allowed_blocks(&U256::from_u64(1_000), &DamperParams::MAINNET);
        assert_eq!(a, 10_368 + 3 * 101);
    }

    #[test]
    fn margin_protects_a_miner_exactly_at_the_cap_from_normal_variance() {
        // Un minero justo en el cap halla ~n bloques; cobrar completo hasta n + 3√n deja fuera
        // sólo desviaciones de más de 3σ.
        let p = DamperParams::MAINNET;
        let w = U256::from_u64(1_000);
        let n = 10_368u64;
        assert!(allowed_blocks(&w, &p) >= n + 3 * isqrt(n));
    }
}
