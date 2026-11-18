//! Compara tamaños de ventana de LWMA con hashrate realista de teléfonos.
//!
//!   cargo run --release --example lwma_sweep
//!
//! Escenarios (el hashrate se define por tiempo, no por número de bloques):
//!   diurno : 12 h a 1000 H/s y 12 h a 4000 H/s, alternando (teléfonos de noche cargando)
//!   caida  : 5000 H/s estable, se apaga el 75 % durante 12 h (día 4) y vuelve
//!   ruido  : 3000 H/s con picos aleatorios de ±50 % cada hora (conectividad irregular)
//!
//! Métricas sobre bloques posteriores al día 2 (se descarta el arranque), media de 30 semillas:
//!   media/T  : tiempo medio de bloque respecto al objetivo (ideal 1.00)
//!   disp     : desviación típica / media del tiempo de bloque (ideal 1.00 = exponencial pura;
//!              más alto => la dificultad "oscila" y añade variabilidad)
//!   p99/T    : percentil 99 del tiempo de bloque respecto a T
//!   max/T    : peor bloque respecto a T
use armax_pow::consensus::{initial_target, pow_limit, TARGET_BLOCK_TIME as T};
use armax_pow::lwma::next_target_with;
use armax_pow::U256;

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
    fn unit(&mut self) -> f64 {
        ((self.next() >> 11) as f64 + 1.0) / (1u64 << 53) as f64
    }
}

/// Devuelve (instante, tiempo de solución) de cada bloque.
fn run(n: usize, hashrate: &dyn Fn(f64) -> f64, days: f64, seed: u64) -> Vec<(f64, f64)> {
    let limit = pow_limit();
    let mut rng = Rng(seed | 1);
    let mut window = vec![(1_000_000u64, initial_target())];
    let (mut elapsed, mut out) = (0.0f64, vec![]);
    while elapsed < days * 86_400.0 {
        let target = next_target_with(&window, T, n, &limit);
        let mean = difficulty(&target) / hashrate(elapsed);
        let st = (-rng.unit().ln() * mean).max(1.0).round();
        elapsed += st;
        window.push((window.last().unwrap().0 + st as u64, target));
        if window.len() > n + 1 {
            window.remove(0);
        }
        out.push((elapsed, st));
    }
    out
}

fn percentile(v: &mut Vec<f64>, p: f64) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((v.len() - 1) as f64 * p) as usize]
}

fn main() {
    let skip = 2.0 * 86_400.0;
    let seeds = 30u64;
    let scenarios: Vec<(&str, Box<dyn Fn(f64) -> f64>, f64)> = vec![
        ("diurno", Box::new(|t| if ((t / 43_200.0).floor() as u64) % 2 == 0 { 1000.0 } else { 4000.0 }), 14.0),
        ("caida ", Box::new(|t| if (3.0 * 86_400.0..3.5 * 86_400.0).contains(&t) { 1250.0 } else { 5000.0 }), 8.0),
        (
            "ruido ",
            Box::new(|t| {
                // pseudo-aleatorio determinista por hora
                let h = (t / 3600.0).floor() as u64;
                let x = (h.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 40) as f64 / (1u64 << 24) as f64;
                3000.0 * (0.5 + x)
            }),
            8.0,
        ),
    ];

    println!("T = {T} s | {seeds} semillas por celda | se descartan los 2 primeros días\n");
    for (name, hr, days) in &scenarios {
        println!("escenario {name}");
        println!("   N  (horas)   media/T    disp    p99/T   max/T");
        for &n in &[20usize, 30, 45, 60, 90] {
            let (mut m, mut d, mut p99, mut mx) = (0.0, 0.0, 0.0, 0.0);
            for s in 0..seeds {
                let r = run(n, hr.as_ref(), *days, 0xA5A5 + s * 7919);
                let mut st: Vec<f64> = r.iter().filter(|(t, _)| *t > skip).map(|(_, x)| *x).collect();
                let mean = st.iter().sum::<f64>() / st.len() as f64;
                let var = st.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / st.len() as f64;
                m += mean / T as f64;
                d += var.sqrt() / mean;
                mx += st.iter().cloned().fold(0.0, f64::max) / T as f64;
                p99 += percentile(&mut st, 0.99) / T as f64;
            }
            let k = seeds as f64;
            println!(
                "  {n:>3}  ({:>4.1} h)   {:>6.3}   {:>6.3}   {:>6.2}   {:>6.1}",
                n as f64 * T as f64 / 3600.0,
                m / k,
                d / k,
                p99 / k,
                mx / k
            );
        }
        println!();
    }
}
