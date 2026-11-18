//! Separa el coste de un intento en (a) relleno del scratchpad y (b) ejecución del programa.
//!
//!   cargo run --release --example split              # iteraciones de consenso (2048)
//!   cargo run --release --example split -- 16384     # prueba con más iteraciones
//!
//! Si "relleno" domina, el PoW mide ancho de banda de memoria (favorece a GPUs/HBM).
//! Si "ejecución" domina, mide latencia de acceso aleatorio (favorece a CPUs móviles).
use armax_vm::gen::{gen_program, AesGen, DOM_SCRATCH};
use armax_vm::sha256::sha256;
use armax_vm::vm::Vm;
use armax_vm::{check_memory, Native, OpTable, Params, Scratchpad};
use std::time::{Duration, Instant};

fn main() {
    let mut p = Params::CONSENSUS;
    if let Some(n) = std::env::args().nth(1).and_then(|a| a.parse::<u32>().ok()) {
        p.iterations = n;
    }
    if let Err(e) = check_memory(p.scratch_bytes, 512 << 20) {
        eprintln!("abortando: {e}");
        return;
    }
    let mut sp = Scratchpad::new(p.scratch_bytes).expect("reserva del scratchpad");
    let table = OpTable::identity();
    let n = 5u32;
    let (mut fill, mut exec) = (Duration::ZERO, Duration::ZERO);

    for i in 0..n {
        let seed = sha256(&i.to_le_bytes());
        let prog = gen_program::<Native>(&seed, p.prog_len);

        let t = Instant::now();
        AesGen::<Native>::new(&seed, DOM_SCRATCH).fill(sp.as_mut_slice());
        fill += t.elapsed();

        let t = Instant::now();
        let mut vm = Vm::<Native>::new(&seed, sp.as_mut_slice());
        for _ in 0..p.iterations {
            vm.exec(&prog, &table);
            vm.commit();
        }
        exec += t.elapsed();
    }

    let f = fill.as_secs_f64() * 1e3 / n as f64;
    let e = exec.as_secs_f64() * 1e3 / n as f64;
    println!("backend AES: {}", <Native as armax_vm::Aes>::NAME);
    println!("iteraciones: {}", p.iterations);
    println!("relleno   : {f:8.1} ms/intento  ({:.1} GB/s)", p.scratch_bytes as f64 / 1e9 / (f / 1e3));
    println!("ejecución : {e:8.1} ms/intento");
    println!("relleno = {:.0}% del intento", 100.0 * f / (f + e));
}
