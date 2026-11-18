//! Medición en x86_64 con AES-NI (solo para comparar con ARM64; no es parte del consenso).
//!
//!   RUSTFLAGS="-C target-feature=+aes,+sse2" cargo run --release --example x86_bench -- [hilos] [intentos_por_hilo]
//!
//! Comprueba primero que el backend AES-NI produce exactamente los mismos bytes que el portable
//! y después mide H/s con los parámetros de consenso (384 MiB por hilo).
#[cfg(not(target_arch = "x86_64"))]
fn main() {
    eprintln!("este ejemplo solo corre en x86_64");
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    use armax_vm::aes::{Aes, State};
    use core::arch::x86_64::*;

    pub struct AesNi;

    #[allow(unused_unsafe)]
    impl Aes for AesNi {
        const NAME: &'static str = "x86_64-aesni";

        #[inline(always)]
        fn enc_round(s: State, rk: State) -> State {
            unsafe {
                let a = _mm_loadu_si128(s.as_ptr() as *const __m128i);
                let k = _mm_loadu_si128(rk.as_ptr() as *const __m128i);
                let mut out = [0u8; 16];
                _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, _mm_aesenc_si128(a, k));
                out
            }
        }

        #[inline(always)]
        fn dec_round(s: State, rk: State) -> State {
            unsafe {
                let a = _mm_loadu_si128(s.as_ptr() as *const __m128i);
                let k = _mm_loadu_si128(rk.as_ptr() as *const __m128i);
                let mut out = [0u8; 16];
                _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, _mm_aesdec_si128(a, k));
                out
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn main() {
    use armax_vm::gen::{AesGen, DOM_SCRATCH};
    use armax_vm::sha256::sha256;
    use armax_vm::{check_memory, pow_hash, Aes, OpTable, Params, Portable, Scratchpad};
    use std::time::Instant;
    use x86::AesNi;

    if !std::arch::is_x86_feature_detected!("aes") {
        eprintln!("este CPU no tiene AES-NI");
        return;
    }
    let args: Vec<String> = std::env::args().collect();
    let threads: usize = args.get(1).and_then(|a| a.parse().ok()).unwrap_or(1);
    let attempts: u32 = args.get(2).and_then(|a| a.parse().ok()).unwrap_or(3);

    // 1. equivalencia bit a bit con el backend portable (parámetros reducidos)
    let t = OpTable::identity();
    let p = Params::TEST;
    let mut sp = vec![0u8; p.scratch_bytes];
    for n in 0u32..6 {
        let a = pow_hash::<AesNi>(&p, &t, &n.to_le_bytes(), &mut sp);
        let b = pow_hash::<Portable>(&p, &t, &n.to_le_bytes(), &mut sp);
        assert_eq!(a, b, "AES-NI y portable difieren en la entrada {n}");
    }
    println!("equivalencia AES-NI == portable: OK (6 entradas)");

    // 2. rendimiento con parámetros de consenso
    let p = Params::CONSENSUS;
    if let Err(e) = check_memory(p.scratch_bytes * threads, 512 << 20) {
        eprintln!("abortando: {e}");
        return;
    }
    println!("backend: {} | hilos: {threads} | {} MiB por hilo | {} iteraciones", AesNi::NAME, p.scratch_bytes >> 20, p.iterations);

    // tiempo de solo el relleno (1 hilo) para ver qué parte del intento es ancho de banda
    {
        let mut s = Scratchpad::new(p.scratch_bytes).unwrap();
        let seed = sha256(b"fill");
        let t0 = Instant::now();
        for _ in 0..3 {
            AesGen::<AesNi>::new(&seed, DOM_SCRATCH).fill(s.as_mut_slice());
        }
        let f = t0.elapsed().as_secs_f64() * 1e3 / 3.0;
        println!("relleno solo: {f:.1} ms ({:.1} GB/s)", p.scratch_bytes as f64 / 1e9 / (f / 1e3));
    }

    let table = OpTable::identity();
    let t0 = Instant::now();
    std::thread::scope(|sc| {
        for id in 0..threads {
            let table = &table;
            sc.spawn(move || {
                let mut s = Scratchpad::new(p.scratch_bytes).unwrap();
                for i in 0..attempts {
                    let input = [(id as u32).to_le_bytes(), i.to_le_bytes()].concat();
                    std::hint::black_box(pow_hash::<AesNi>(&p, table, &input, s.as_mut_slice()));
                }
            });
        }
    });
    let wall = t0.elapsed().as_secs_f64();
    let total = threads as f64 * attempts as f64;
    println!(
        "{} intentos en {:.2} s => {:.2} H/s en total, {:.2} H/s por hilo ({:.0} ms/intento por hilo)",
        total as u64,
        wall,
        total / wall,
        total / wall / threads as f64,
        wall * 1e3 / attempts as f64
    );
}
