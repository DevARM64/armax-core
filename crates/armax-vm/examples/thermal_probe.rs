//! Sonda para decidir cuántos hilos de minado aguanta TU teléfono.
//!
//!   cargo run --release --example thermal_probe -- <hilos> <segundos> [intervalo_s] [tope_°C]
//!
//! Ejemplos (déjalo enfriar 10-15 min entre una prueba y la siguiente):
//!   cargo run --release --example thermal_probe -- 1 300
//!   cargo run --release --example thermal_probe -- 2 300
//!   cargo run --release --example thermal_probe -- 3 300
//!
//! Corre `hilos` hilos de minado con los parámetros de consenso (384 MiB por hilo) y cada
//! `intervalo_s` segundos (30 por defecto) imprime: H/s total y por hilo, temperatura de la
//! batería, % de batería, corriente y memoria libre. Se detiene sola si la batería llega a
//! `tope_°C` (42 por defecto, el límite del proyecto) o si queda poca memoria libre.
//!
//! En Termux conviene `termux-wake-lock` antes de empezar, para que Android no suspenda el proceso.
//! La temperatura se lee de /sys/class/power_supply/battery/temp; si no es legible, se intenta
//! `termux-battery-status` (paquete Termux:API).
//!
//! Cómo elegir: quédate con el mayor número de hilos para el que (1) la temperatura de la batería
//! se estabilice por debajo de ~40 °C, (2) los H/s por hilo no se desplomen respecto a 1 hilo,
//! (3) el consumo te parezca aceptable y (4) el sistema no mate el proceso.
use armax_vm::mem::mem_available_bytes;
use armax_vm::{check_memory, pow_hash, Native, OpTable, Params, Scratchpad};
use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

fn read_f64(path: &str) -> Option<f64> {
    fs::read_to_string(path).ok()?.trim().parse::<f64>().ok()
}

/// Valor numérico de `"clave": 12.3` en el JSON de termux-battery-status (sin dependencias).
fn json_num(s: &str, key: &str) -> Option<f64> {
    let k = format!("\"{key}\"");
    let rest = &s[s.find(&k)? + k.len()..];
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    let end = rest.find(|c: char| !(c.is_ascii_digit() || c == '.' || c == '-')).unwrap_or(rest.len());
    rest[..end].parse().ok()
}

struct Sample {
    battery_c: Option<f64>,
    percent: Option<f64>,
    current_ma: Option<f64>,
    soc_c: Option<f64>,
}

fn sample() -> Sample {
    let base = "/sys/class/power_supply/battery";
    let mut battery_c = read_f64(&format!("{base}/temp")).map(|v| v / 10.0); // décimas de °C
    let mut percent = read_f64(&format!("{base}/capacity"));
    let current_ma = read_f64(&format!("{base}/current_now")).map(|v| v / 1000.0); // µA -> mA

    if battery_c.is_none() || percent.is_none() {
        if let Ok(out) = Command::new("termux-battery-status").output() {
            let s = String::from_utf8_lossy(&out.stdout);
            battery_c = battery_c.or(json_num(&s, "temperature"));
            percent = percent.or(json_num(&s, "percentage"));
        }
    }

    // Temperatura máxima de las zonas térmicas legibles (suele ser el SoC); informativa.
    let mut soc_c: Option<f64> = None;
    if let Ok(dir) = fs::read_dir("/sys/class/thermal") {
        for e in dir.flatten() {
            if !e.file_name().to_string_lossy().starts_with("thermal_zone") {
                continue;
            }
            if let Some(mut v) = read_f64(&e.path().join("temp").to_string_lossy()) {
                if v > 1000.0 {
                    v /= 1000.0;
                }
                if (10.0..110.0).contains(&v) {
                    soc_c = Some(soc_c.map_or(v, |m: f64| m.max(v)));
                }
            }
        }
    }
    Sample { battery_c, percent, current_ma, soc_c }
}

#[cfg(test)]
mod tests {
    use super::json_num;

    #[test]
    fn parses_termux_battery_status() {
        // formato de salida de `termux-battery-status` (Termux:API)
        let s = "{\n  \"health\": \"GOOD\",\n  \"percentage\": 57,\n  \"plugged\": \"UNPLUGGED\",\n  \"status\": \"DISCHARGING\",\n  \"temperature\": 31.5,\n  \"current\": -250000\n}";
        assert_eq!(json_num(s, "percentage"), Some(57.0));
        assert_eq!(json_num(s, "temperature"), Some(31.5));
        assert_eq!(json_num(s, "current"), Some(-250000.0));
        assert_eq!(json_num(s, "missing"), None);
        assert_eq!(json_num("{\"temperature\":null}", "temperature"), None);
        assert_eq!(json_num("{\"temperature\":40}", "temperature"), Some(40.0)); // compacto, sin espacios
    }
}

fn fmt(v: Option<f64>, unit: &str) -> String {
    v.map_or("  n/d".to_string(), |x| format!("{x:>5.1}{unit}"))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let threads: usize = args.get(1).and_then(|a| a.parse().ok()).unwrap_or(1).max(1);
    let secs: u64 = args.get(2).and_then(|a| a.parse().ok()).unwrap_or(300);
    let interval: u64 = args.get(3).and_then(|a| a.parse().ok()).unwrap_or(30).max(1);
    let limit_c: f64 = args.get(4).and_then(|a| a.parse().ok()).unwrap_or(42.0);
    // "test" como quinto argumento: parámetros reducidos para comprobar que la sonda funciona
    let p = if args.get(5).map(|s| s == "test").unwrap_or(false) { Params::TEST } else { Params::CONSENSUS };

    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    println!("núcleos visibles: {cores} | hilos de prueba: {threads} | {} MiB por hilo", p.scratch_bytes >> 20);
    if let Some(avail) = mem_available_bytes() {
        let by_mem = (avail.saturating_sub(1 << 30) / p.scratch_bytes as u64) as usize;
        println!(
            "memoria disponible: {} MiB  =>  tope por memoria (dejando 1 GiB libre): {} hilos",
            avail >> 20,
            by_mem
        );
    }
    if let Err(e) = check_memory(p.scratch_bytes * threads, 1 << 30) {
        eprintln!("abortando antes de empezar: {e}");
        return;
    }

    let s0 = sample();
    println!(
        "inicio: batería {} | {} | corriente {} | SoC {}",
        fmt(s0.battery_c, "°C"),
        fmt(s0.percent, "%"),
        fmt(s0.current_ma, "mA"),
        fmt(s0.soc_c, "°C")
    );
    if s0.battery_c.is_none() {
        println!("AVISO: no se puede leer la temperatura; no habrá corte automático por calor.");
    }
    println!("tope de temperatura de batería: {limit_c:.1} °C | duración: {secs} s | intervalo: {interval} s\n");
    println!("  t(s)   H/s total  H/s/hilo   batería     %      corriente   SoC(máx)  memoria libre");

    let stop = AtomicBool::new(false);
    let attempts = AtomicU64::new(0);
    let table = OpTable::identity();
    let start = Instant::now();
    let mut history: Vec<(f64, Option<f64>)> = vec![]; // (H/s total, temp batería)
    let mut stopped_by = "tiempo".to_string();

    std::thread::scope(|sc| {
        for id in 0..threads {
            let (stop, attempts, table) = (&stop, &attempts, &table);
            sc.spawn(move || {
                let mut sp = Scratchpad::new(p.scratch_bytes).expect("reserva del scratchpad");
                let mut n = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    let input = [(id as u64).to_le_bytes(), n.to_le_bytes()].concat();
                    std::hint::black_box(pow_hash::<Native>(&p, table, &input, sp.as_mut_slice()));
                    attempts.fetch_add(1, Ordering::Relaxed);
                    n += 1;
                }
            });
        }

        let (mut last_t, mut last_n) = (Instant::now(), 0u64);
        while start.elapsed() < Duration::from_secs(secs) {
            std::thread::sleep(Duration::from_secs(interval.min(secs)));
            let n = attempts.load(Ordering::Relaxed);
            let dt = last_t.elapsed().as_secs_f64();
            let hps = (n - last_n) as f64 / dt;
            (last_t, last_n) = (Instant::now(), n);

            let s = sample();
            let mem = mem_available_bytes().map(|b| b >> 20);
            println!(
                "{:>6.0}   {:>8.2}   {:>8.2}   {}   {}   {}   {}   {}",
                start.elapsed().as_secs_f64(),
                hps,
                hps / threads as f64,
                fmt(s.battery_c, "°C"),
                fmt(s.percent, "%"),
                fmt(s.current_ma, "mA"),
                fmt(s.soc_c, "°C"),
                mem.map_or("n/d".into(), |m| format!("{m} MiB"))
            );
            history.push((hps, s.battery_c));

            if let Some(t) = s.battery_c {
                if t >= limit_c {
                    stopped_by = format!("batería a {t:.1} °C (tope {limit_c:.1})");
                    break;
                }
            }
            if let Some(m) = mem {
                if m < 300 {
                    stopped_by = format!("memoria libre baja ({m} MiB)");
                    break;
                }
            }
        }
        stop.store(true, Ordering::Relaxed);
    });

    let s1 = sample();
    println!("\n== resumen ==  (se detuvo por: {stopped_by})");
    // promedio de la segunda mitad (ya calentado)
    let half = history.len() / 2;
    let tail = &history[half..];
    if !tail.is_empty() {
        let avg = tail.iter().map(|h| h.0).sum::<f64>() / tail.len() as f64;
        println!("H/s total (segunda mitad): {avg:.2}  =>  {:.2} por hilo", avg / threads as f64);
    }
    if let (Some(a), Some(b)) = (s0.battery_c, s1.battery_c) {
        println!("batería: {a:.1} °C -> {b:.1} °C ({:+.1})", b - a);
    }
    if let (Some(a), Some(b)) = (s0.percent, s1.percent) {
        println!("carga: {a:.0} % -> {b:.0} % ({:+.0} puntos en {:.0} s)", b - a, start.elapsed().as_secs_f64());
    }
    println!("Compara el H/s por hilo con la prueba de 1 hilo: si cae mucho, los hilos extra no compensan.");
}
