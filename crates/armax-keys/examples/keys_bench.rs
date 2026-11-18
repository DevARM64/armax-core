//! Tiempos de las operaciones de llaves en este equipo.
//!   cargo run --release -p armax-keys --example keys_bench
use armax_keys::bip39::Mnemonic;
use armax_keys::ed25519::{public_key_from_seed, sign, verify};
use std::time::Instant;

fn time<F: FnMut()>(name: &str, n: u32, mut f: F) {
    f(); // calentamiento
    let t = Instant::now();
    for _ in 0..n {
        f();
    }
    let per = t.elapsed().as_secs_f64() / n as f64;
    println!("{name:<34} {:>9.3} ms   ({:>8.0} por segundo)", per * 1e3, 1.0 / per);
}

fn main() {
    let seed = [7u8; 32];
    let msg = [9u8; 32];
    let pk = public_key_from_seed(&seed);
    let sig = sign(&seed, &msg);
    time("clave pública desde semilla", 200, || {
        std::hint::black_box(public_key_from_seed(&seed));
    });
    time("firmar", 200, || {
        std::hint::black_box(sign(&seed, &msg));
    });
    time("verificar firma", 200, || {
        assert!(verify(&pk, &msg, &sig));
    });
    let m = Mnemonic::from_entropy(&[1u8; 16]).unwrap();
    time("BIP-39 frase -> semilla (PBKDF2)", 20, || {
        std::hint::black_box(m.to_seed(""));
    });
    let v = 1.0
        / ({
            let t = Instant::now();
            for _ in 0..200 {
                assert!(verify(&pk, &msg, &sig));
            }
            t.elapsed().as_secs_f64() / 200.0
        });
    println!("\nUn bloque con 64 entradas por transacción y 100 transacciones son 6400 firmas: ~{:.1} s de verificación en un núcleo.", 6400.0 / v);
}
