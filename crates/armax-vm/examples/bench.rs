//! Mide el coste de un intento de PoW. Uso:
//!   cargo run --release --example bench            # parámetros reducidos
//!   cargo run --release --example bench -- full    # 384 MiB reales (1 hilo)
use armax_vm::{check_memory, pow_hash, Native, OpTable, Params, Scratchpad};
use std::time::Instant;

fn main() {
    let full = std::env::args().any(|a| a == "full");
    let p = if full { Params::CONSENSUS } else { Params::TEST };
    let n: u32 = if full { 3 } else { 200 };

    println!("backend AES: {}", <Native as armax_vm::Aes>::NAME);
    println!("scratchpad: {} MiB, programa: {} instr, iteraciones: {}", p.scratch_bytes >> 20, p.prog_len, p.iterations);

    if let Err(e) = check_memory(p.scratch_bytes, 512 << 20) {
        eprintln!("abortando: {e}");
        return;
    }
    let mut sp = Scratchpad::new(p.scratch_bytes).expect("reserva del scratchpad");
    let table = OpTable::identity();

    let t = Instant::now();
    let mut last = [0u8; 32];
    for i in 0..n {
        last = pow_hash::<Native>(&p, &table, &i.to_le_bytes(), sp.as_mut_slice());
    }
    let dt = t.elapsed();
    let per = dt.as_secs_f64() / n as f64;
    println!("{n} intentos en {:.2?}  =>  {:.1} ms/intento  =>  {:.2} H/s por hilo", dt, per * 1e3, 1.0 / per);
    println!("último digest: {:02x}{:02x}{:02x}{:02x}...", last[0], last[1], last[2], last[3]);
}
