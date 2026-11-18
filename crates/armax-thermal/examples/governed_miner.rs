//! Minero de prueba controlado por el gobernador térmico, para correr en Termux.
//!
//!   cargo run --release --example governed_miner -- [segundos] [intervalo_s] [opciones]
//!
//! Ejemplos:
//!   cargo run --release --example governed_miner -- 1800            # 30 min, cada 10 s, solo cargando
//!   cargo run --release --example governed_miner -- 600 10 any-power # también sin cargador (≥ 15 % de batería)
//!
//! Opciones:  any-power  minar también sin cargador      no-temp  permitir sin sensor de temperatura
//!            max=N      máximo de hilos (por defecto 2) test     parámetros reducidos (solo comprobar)
//!
//! Requiere `termux-battery-status` (paquete Termux:API) para leer la temperatura y el cargador.
//! Cada `intervalo_s` lee los sensores, el gobernador decide cuántos hilos corren y se imprime
//! una línea. Los hilos pausados liberan sus 384 MiB.
use armax_thermal::{AutoSource, Governor, SensorSource, ThermalConfig};
use armax_vm::{pow_hash, Native, OpTable, Params, Scratchpad};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let nums: Vec<u64> = args.iter().filter_map(|a| a.parse().ok()).collect();
    let secs = nums.first().copied().unwrap_or(600);
    let interval = nums.get(1).copied().unwrap_or(10).max(1);
    let has = |f: &str| args.iter().any(|a| a == f);

    let mut cfg = ThermalConfig::default();
    cfg.require_charging = !has("any-power");
    cfg.allow_without_temperature = has("no-temp");
    if let Some(n) = args.iter().find_map(|a| a.strip_prefix("max=")).and_then(|v| v.parse::<u8>().ok()) {
        cfg.max_threads = n;
    }
    let p = if has("test") { Params::TEST } else { Params::CONSENSUS };
    if has("test") {
        cfg.mem_per_thread_mib = 1;
        cfg.mem_headroom_mib = 0;
    }
    let mut gov = match Governor::new(cfg) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("configuración inválida: {e}");
            return;
        }
    };

    println!(
        "hilos máx {} | 2 hilos si batería ≤ {:.0} °C, 1 hilo desde {:.0} °C, pausa a {:.0} °C, reanuda ≤ {:.0} °C",
        cfg.max_threads, cfg.two_threads_below_c, cfg.one_thread_above_c, cfg.pause_at_c, cfg.resume_below_c
    );
    println!(
        "solo con cargador: {} | duración {secs} s | intervalo {interval} s | {} MiB por hilo\n",
        cfg.require_charging,
        p.scratch_bytes >> 20
    );
    println!("  t(s)  hilos  motivo                   H/s    batería    carga   memoria libre");

    let max = cfg.max_threads as usize;
    let desired = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let attempts = AtomicU64::new(0);
    let table = OpTable::identity();
    let start = Instant::now();

    std::thread::scope(|sc| {
        for id in 0..max {
            let (desired, stop, attempts, table) = (&desired, &stop, &attempts, &table);
            sc.spawn(move || {
                let mut sp: Option<Scratchpad> = None;
                let mut n = 0u64;
                while !stop.load(Relaxed) {
                    if id >= desired.load(Relaxed) {
                        sp = None; // pausado: libera la memoria
                        std::thread::sleep(Duration::from_millis(300));
                        continue;
                    }
                    if sp.is_none() {
                        match Scratchpad::new(p.scratch_bytes) {
                            Ok(s) => sp = Some(s),
                            Err(_) => {
                                std::thread::sleep(Duration::from_secs(1));
                                continue;
                            }
                        }
                    }
                    let input = [(id as u64).to_le_bytes(), n.to_le_bytes()].concat();
                    std::hint::black_box(pow_hash::<Native>(&p, table, &input, sp.as_mut().unwrap().as_mut_slice()));
                    attempts.fetch_add(1, Relaxed);
                    n += 1;
                }
            });
        }

        let mut src = AutoSource::new();
        let (mut last_t, mut last_n) = (Instant::now(), 0u64);
        loop {
            let s = src.read(start.elapsed().as_secs());
            let d = gov.update(&s);
            desired.store(d.threads as usize, Relaxed);

            let n = attempts.load(Relaxed);
            let hps = (n - last_n) as f64 / last_t.elapsed().as_secs_f64();
            (last_t, last_n) = (Instant::now(), n);
            println!(
                "{:>6}  {:>3}   {:<22} {:>6.2}   {}   {}   {}",
                start.elapsed().as_secs(),
                d.threads,
                format!("{:?}", d.reason),
                hps,
                s.battery_temp_c.map_or("   n/d".into(), |t| format!("{t:>5.1}°C")),
                s.battery_pct.map_or("  n/d".into(), |p| format!("{p:>4}%")),
                s.mem_available_mib.map_or("n/d".into(), |m| format!("{m} MiB")),
            );

            if start.elapsed() >= Duration::from_secs(secs) {
                break;
            }
            std::thread::sleep(Duration::from_secs(interval));
        }
        stop.store(true, Relaxed);
    });
    println!("\nfin. Si algún motivo es NoTemperatureSensor / NoChargingInfo, comprueba `termux-battery-status`.");
}
