//! Ajuste de dificultad LWMA (media móvil ponderada linealmente, zawy12) en espacio de *targets*.
//!
//! Con `target ∝ 1/dificultad`, la media armónica de dificultades de LWMA-1 es exactamente la
//! media aritmética de targets, así que todo se calcula con enteros de 256 bits:
//!
//! ```text
//!   st_i   = clamp(ts_i − ts_{i−1}, −6T, 6T)          i = 1..n
//!   L      = max( Σ i·st_i , n²·T/20 )                (ponderación lineal: pesa más lo reciente)
//!   avg    = Σ ⌊target_i / n⌋
//!   next   = avg · L / (T · n(n+1)/2)                 (acotado a [1, pow_limit])
//! ```
//!
//! Si los bloques llegan más lentos de lo previsto, `L` crece y el target sube (más fácil);
//! si llegan más rápido, baja. El mínimo de `L` limita la subida de dificultad a ~10x por bloque.
//!
//! Sin flotantes: el resultado es idéntico en cualquier plataforma.

use crate::consensus::{pow_limit, LWMA_SOLVETIME_CLAMP, LWMA_WINDOW, TARGET_BLOCK_TIME};
use crate::u256::U256;

/// Una entrada de la ventana: (timestamp, target del bloque).
pub type WindowEntry = (u64, U256);

/// Target del siguiente bloque con los parámetros de consenso.
/// `window` va de más antiguo a más reciente y termina en el padre del bloque a validar.
pub fn next_target(window: &[WindowEntry]) -> U256 {
    next_target_with(window, TARGET_BLOCK_TIME, LWMA_WINDOW, &pow_limit())
}

/// Versión parametrizable (para tests y simulaciones).
pub fn next_target_with(window: &[WindowEntry], t: u64, max_n: usize, limit: &U256) -> U256 {
    assert!(!window.is_empty(), "la ventana necesita al menos el bloque padre");
    assert!(t > 0 && max_n > 0);
    let last = window[window.len() - 1].1;
    if window.len() < 2 {
        return clamp_target(last, limit);
    }

    let n = (window.len() - 1).min(max_n);
    let w = &window[window.len() - n - 1..];

    let clamp = LWMA_SOLVETIME_CLAMP as i128 * t as i128;
    let mut weighted: i128 = 0;
    let mut avg = U256::ZERO;
    for i in 1..=n {
        let st = (w[i].0 as i128 - w[i - 1].0 as i128).clamp(-clamp, clamp);
        weighted += i as i128 * st;
        // Σ⌊x/n⌋ ≤ n·⌊MAX/n⌋ ≤ MAX: no puede desbordar.
        avg = avg
            .checked_add(w[i].1.div_u64(n as u64))
            .expect("la suma de targets/n no desborda");
    }

    let n64 = n as u64;
    let min_l = (n64 * n64 * t / 20).max(1) as i128;
    let l = weighted.max(min_l) as u64;
    let k = n64 * (n64 + 1) / 2;

    match avg.mul_div_u64(l, k * t) {
        Some(next) => clamp_target(next, limit),
        None => *limit, // desbordó 256 bits: más fácil que el límite
    }
}

fn clamp_target(t: U256, limit: &U256) -> U256 {
    if t > *limit {
        *limit
    } else if t.is_zero() {
        U256::ONE
    } else {
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::initial_target;

    fn to_f64(x: &U256) -> f64 {
        x.0.iter().enumerate().map(|(i, &l)| l as f64 * 2f64.powi(64 * i as i32)).sum()
    }
    fn difficulty(t: &U256) -> f64 {
        2f64.powi(256) / to_f64(t)
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        /// Uniforme en (0, 1].
        fn unit(&mut self) -> f64 {
            ((self.next() >> 11) as f64 + 1.0) / (1u64 << 53) as f64
        }
    }

    fn flat_window(n: usize, st: u64, target: U256) -> Vec<WindowEntry> {
        (0..=n).map(|i| (1_000_000 + i as u64 * st, target)).collect()
    }

    #[test]
    fn single_block_returns_parent_target() {
        let t = initial_target();
        assert_eq!(next_target(&[(0, t)]), t);
    }

    #[test]
    fn steady_state_keeps_target() {
        let t = initial_target();
        let next = next_target(&flat_window(LWMA_WINDOW, TARGET_BLOCK_TIME, t));
        let diff = if next > t { next.checked_sub(t) } else { t.checked_sub(next) }.unwrap();
        // solo la pérdida de redondeo de Σ⌊t/n⌋ (< n unidades)
        assert!(diff < U256::from_u64(LWMA_WINDOW as u64 + 1), "{diff:?}");
    }

    #[test]
    fn slow_blocks_raise_target_fast_blocks_lower_it() {
        let t = initial_target();
        let slow = next_target(&flat_window(LWMA_WINDOW, 2 * TARGET_BLOCK_TIME, t));
        let fast = next_target(&flat_window(LWMA_WINDOW, TARGET_BLOCK_TIME / 2, t));
        assert!(slow > t && fast < t);
        // el factor es ~2x y ~0.5x
        let r_slow = to_f64(&slow) / to_f64(&t);
        let r_fast = to_f64(&fast) / to_f64(&t);
        assert!((r_slow - 2.0).abs() < 0.01, "{r_slow}");
        assert!((r_fast - 0.5).abs() < 0.01, "{r_fast}");
    }

    #[test]
    fn increase_in_difficulty_per_block_is_bounded() {
        // bloques de 1 s en toda la ventana: el target baja como mucho ~10x
        let t = initial_target();
        let next = next_target(&flat_window(LWMA_WINDOW, 1, t));
        let ratio = to_f64(&t) / to_f64(&next);
        assert!(ratio > 5.0 && ratio < 11.0, "{ratio}");
    }

    #[test]
    fn one_manipulated_timestamp_has_bounded_effect() {
        let t = initial_target();
        let mut w = flat_window(LWMA_WINDOW, TARGET_BLOCK_TIME, t);
        let last = w.len() - 1;
        w[last].0 += 10 * 365 * 86_400; // el último bloque declara +10 años
        let next = next_target(&w);
        let r = to_f64(&next) / to_f64(&t);
        // st se acota a 6T y pesa n/k: efecto máximo ~ (1 + 5·n/k)
        assert!(r < 1.0 + 5.0 * LWMA_WINDOW as f64 / (LWMA_WINDOW * (LWMA_WINDOW + 1) / 2) as f64 + 0.01, "{r}");
        assert!(r > 1.0);
    }

    #[test]
    fn negative_solvetimes_do_not_break_it() {
        // timestamps desordenados (permitido mientras superen la MTP): no debe entrar en pánico
        let t = initial_target();
        let mut w = flat_window(LWMA_WINDOW, TARGET_BLOCK_TIME, t);
        let mid = LWMA_WINDOW / 2;
        w[mid].0 += 5000;
        w[mid + 1].0 -= 5000;
        let next = next_target(&w);
        assert!(!next.is_zero() && next <= pow_limit());
    }

    #[test]
    fn never_exceeds_limit_or_hits_zero() {
        let limit = pow_limit();
        // bloques muy lentos desde el target máximo: se queda en el límite
        let slow = next_target(&flat_window(LWMA_WINDOW, 1_000_000, limit));
        assert_eq!(slow, limit);
        // target mínimo con bloques instantáneos: no baja de 1
        let fast = next_target(&flat_window(LWMA_WINDOW, 1, U256::from_u64(3)));
        assert!(fast >= U256::ONE);
    }

    #[test]
    fn short_history_uses_available_blocks() {
        let t = initial_target();
        let w = flat_window(3, 2 * TARGET_BLOCK_TIME, t);
        let next = next_target(&w);
        let r = to_f64(&next) / to_f64(&t);
        assert!((r - 2.0).abs() < 0.01, "{r}");
    }

    /// Simula la red con hashrate variable: tiempo de solución ~ Exp(media = D / H).
    fn simulate(phases: &[(usize, f64)], seed: u64) -> Vec<Vec<f64>> {
        let mut rng = Rng(seed);
        let mut window: Vec<WindowEntry> = vec![(1_000_000, initial_target())];
        let mut out = vec![];
        for &(count, h) in phases {
            let mut sts = vec![];
            for _ in 0..count {
                let target = next_target(&window);
                let mean = difficulty(&target) / h;
                let st = (-rng.unit().ln() * mean).max(1.0).round() as u64;
                let ts = window.last().unwrap().0 + st;
                window.push((ts, target));
                if window.len() > LWMA_WINDOW + 1 {
                    window.remove(0);
                }
                sts.push(st as f64);
            }
            out.push(sts);
        }
        out
    }

    fn mean(v: &[f64]) -> f64 {
        v.iter().sum::<f64>() / v.len() as f64
    }

    #[test]
    fn tracks_hashrate_drop_and_recovery() {
        let t = TARGET_BLOCK_TIME as f64;
        // 1000 teléfonos (5000 H/s) -> se apaga el 75 % -> vuelven. Dificultad inicial ≈ 1 teléfono.
        let r = simulate(&[(800, 5000.0), (800, 1250.0), (800, 5000.0)], 0xC0FFEE);

        for (i, phase) in r.iter().enumerate() {
            let settled = &phase[phase.len() - 400..];
            let m = mean(settled);
            assert!((0.85 * t..=1.15 * t).contains(&m), "fase {i}: media {m:.1}s (objetivo {t})");
        }
        // Tras la caída del 75 %, a los 60-120 bloques ya está cerca del objetivo.
        let recov = mean(&r[1][60..120]);
        assert!(recov < 1.35 * t, "recuperación lenta: {recov:.1}s");
        // En el pico de la caída ningún bloque supera lo razonable (sin atasco)
        let worst = r[1].iter().cloned().fold(0.0, f64::max);
        assert!(worst < 40.0 * t, "bloque de {worst:.0}s");
    }

    #[test]
    fn nightly_cycle_stays_stable() {
        // ciclo diario: 12 h de día a 1000 H/s y 12 h de noche a 4000 H/s (teléfonos cargando)
        let t = TARGET_BLOCK_TIME as f64;
        let mut phases = vec![];
        for _ in 0..6 {
            phases.push((144, 1000.0)); // ≈ 12 h a 300 s
            phases.push((144, 4000.0));
        }
        let r = simulate(&phases, 12345);
        let all: Vec<f64> = r.iter().skip(2).flatten().cloned().collect();
        let m = mean(&all);
        assert!((0.8 * t..=1.25 * t).contains(&m), "media global {m:.1}s");
    }
}
