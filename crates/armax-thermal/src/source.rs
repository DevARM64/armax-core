//! Fuentes de lecturas del dispositivo para el gobernador.
//!
//! * `SysfsSource`      — `/sys/class/power_supply/battery/{temp,capacity,status}` (Linux/Android con acceso).
//! * `TermuxApiSource`  — `termux-battery-status` (paquete Termux:API); es lo que funciona en Termux sin root.
//! * `AutoSource`       — prueba sysfs y completa lo que falte con Termux:API.
//!
//! En la app Android definitiva, estas lecturas vendrán de `BatteryManager` y `PowerManager`
//! (que además da `isInteractive()` para saber si la pantalla está en uso) a través del puente
//! JNI: bastará implementar `SensorSource` allí. Aquí `screen_on` queda siempre en `None`.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use armax_vm::mem::mem_available_bytes;

use crate::governor::Sensors;

pub trait SensorSource {
    fn read(&mut self, now_s: u64) -> Sensors;
}

// ---- analizadores (puros, probados) --------------------------------------------------------

/// `/sys/class/power_supply/battery/temp`: décimas de °C ("370" = 37.0 °C).
pub fn parse_tenths_c(s: &str) -> Option<f64> {
    s.trim().parse::<f64>().ok().map(|v| v / 10.0)
}

pub fn parse_pct(s: &str) -> Option<u8> {
    let v: f64 = s.trim().parse().ok()?;
    (0.0..=100.0).contains(&v).then(|| v.round() as u8)
}

/// `/sys/class/power_supply/battery/status` -> ¿hay cargador conectado?
/// "Full" y "Not charging" también implican cargador (batería llena o protección de carga).
pub fn parse_sysfs_status(s: &str) -> Option<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "charging" | "full" | "not charging" => Some(true),
        "discharging" => Some(false),
        _ => None,
    }
}

/// Valor numérico de `"clave": 12.3` (JSON simple, sin dependencias).
pub fn json_num(s: &str, key: &str) -> Option<f64> {
    let k = format!("\"{key}\"");
    let rest = &s[s.find(&k)? + k.len()..];
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    let end = rest.find(|c: char| !(c.is_ascii_digit() || c == '.' || c == '-')).unwrap_or(rest.len());
    rest[..end].parse().ok()
}

/// Valor de texto de `"clave": "VALOR"`.
pub fn json_str<'a>(s: &'a str, key: &str) -> Option<&'a str> {
    let k = format!("\"{key}\"");
    let rest = &s[s.find(&k)? + k.len()..];
    let rest = rest.trim_start().strip_prefix(':')?.trim_start().strip_prefix('"')?;
    Some(&rest[..rest.find('"')?])
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Battery {
    pub temp_c: Option<f64>,
    pub pct: Option<u8>,
    pub charging: Option<bool>,
}

/// Salida de `termux-battery-status`:
/// `{"health":"GOOD","percentage":57,"plugged":"PLUGGED_AC","status":"CHARGING","temperature":31.5,...}`
pub fn parse_termux_json(s: &str) -> Battery {
    let charging = match json_str(s, "plugged") {
        Some(p) => Some(!p.eq_ignore_ascii_case("UNPLUGGED")),
        None => json_str(s, "status").and_then(|st| match st.to_ascii_uppercase().as_str() {
            "CHARGING" | "FULL" | "NOT_CHARGING" => Some(true),
            "DISCHARGING" => Some(false),
            _ => None,
        }),
    };
    Battery {
        temp_c: json_num(s, "temperature"),
        pct: json_num(s, "percentage").filter(|p| (0.0..=100.0).contains(p)).map(|p| p.round() as u8),
        charging,
    }
}

/// Completa con `fallback` los campos que `primary` no tenga.
pub fn merge(primary: Sensors, fallback: Sensors) -> Sensors {
    Sensors {
        now_s: primary.now_s,
        battery_temp_c: primary.battery_temp_c.or(fallback.battery_temp_c),
        charging: primary.charging.or(fallback.charging),
        battery_pct: primary.battery_pct.or(fallback.battery_pct),
        screen_on: primary.screen_on.or(fallback.screen_on),
        mem_available_mib: primary.mem_available_mib.or(fallback.mem_available_mib),
    }
}

fn mem_mib() -> Option<u64> {
    mem_available_bytes().map(|b| b >> 20)
}

// ---- fuentes -----------------------------------------------------------------------------

pub struct SysfsSource {
    base: PathBuf,
}

impl SysfsSource {
    pub fn new() -> Self {
        Self::with_base("/sys/class/power_supply/battery")
    }
    pub fn with_base(base: impl Into<PathBuf>) -> Self {
        Self { base: base.into() }
    }
}

impl Default for SysfsSource {
    fn default() -> Self {
        Self::new()
    }
}

impl SensorSource for SysfsSource {
    fn read(&mut self, now_s: u64) -> Sensors {
        let rd = |name: &str| fs::read_to_string(self.base.join(name)).ok();
        Sensors {
            now_s,
            battery_temp_c: rd("temp").and_then(|s| parse_tenths_c(&s)),
            charging: rd("status").and_then(|s| parse_sysfs_status(&s)),
            battery_pct: rd("capacity").and_then(|s| parse_pct(&s)),
            screen_on: None,
            mem_available_mib: mem_mib(),
        }
    }
}

#[derive(Default)]
pub struct TermuxApiSource;

impl SensorSource for TermuxApiSource {
    fn read(&mut self, now_s: u64) -> Sensors {
        let b = Command::new("termux-battery-status")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| parse_termux_json(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or_default();
        Sensors {
            now_s,
            battery_temp_c: b.temp_c,
            charging: b.charging,
            battery_pct: b.pct,
            screen_on: None,
            mem_available_mib: mem_mib(),
        }
    }
}

/// sysfs primero; si falta temperatura, estado de carga o porcentaje, completa con Termux:API.
pub struct AutoSource {
    sysfs: SysfsSource,
    termux: TermuxApiSource,
}

impl AutoSource {
    pub fn new() -> Self {
        Self { sysfs: SysfsSource::new(), termux: TermuxApiSource }
    }
}

impl Default for AutoSource {
    fn default() -> Self {
        Self::new()
    }
}

impl SensorSource for AutoSource {
    fn read(&mut self, now_s: u64) -> Sensors {
        let s = self.sysfs.read(now_s);
        if s.battery_temp_c.is_none() || s.charging.is_none() || s.battery_pct.is_none() {
            merge(s, self.termux.read(now_s))
        } else {
            s
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TERMUX_CHARGING: &str = "{\n  \"health\": \"GOOD\",\n  \"percentage\": 97,\n  \"plugged\": \"PLUGGED_AC\",\n  \"status\": \"CHARGING\",\n  \"temperature\": 37.0,\n  \"current\": 250000\n}";
    const TERMUX_UNPLUGGED: &str = "{\"health\":\"GOOD\",\"percentage\":21,\"plugged\":\"UNPLUGGED\",\"status\":\"DISCHARGING\",\"temperature\":35.5}";

    #[test]
    fn parses_sysfs_values() {
        assert_eq!(parse_tenths_c("370\n"), Some(37.0));
        assert_eq!(parse_tenths_c("-25"), Some(-2.5));
        assert_eq!(parse_tenths_c("n/a"), None);
        assert_eq!(parse_pct("97\n"), Some(97));
        assert_eq!(parse_pct("101"), None);
        assert_eq!(parse_sysfs_status("Charging\n"), Some(true));
        assert_eq!(parse_sysfs_status("Full"), Some(true));
        assert_eq!(parse_sysfs_status("Not charging"), Some(true));
        assert_eq!(parse_sysfs_status("Discharging"), Some(false));
        assert_eq!(parse_sysfs_status("Unknown"), None);
    }

    #[test]
    fn parses_termux_battery_json() {
        let b = parse_termux_json(TERMUX_CHARGING);
        assert_eq!(b, Battery { temp_c: Some(37.0), pct: Some(97), charging: Some(true) });
        let b = parse_termux_json(TERMUX_UNPLUGGED);
        assert_eq!(b, Battery { temp_c: Some(35.5), pct: Some(21), charging: Some(false) });
        // sin "plugged": se usa "status"
        let b = parse_termux_json("{\"percentage\":50,\"status\":\"FULL\",\"temperature\":30}");
        assert_eq!(b.charging, Some(true));
        // basura o campos nulos: todo desconocido, sin pánico
        assert_eq!(parse_termux_json("nada"), Battery::default());
        assert_eq!(parse_termux_json("{\"temperature\":null}").temp_c, None);
    }

    #[test]
    fn merge_fills_only_missing_fields() {
        let a = Sensors { now_s: 5, battery_temp_c: Some(30.0), ..Default::default() };
        let b = Sensors {
            now_s: 99,
            battery_temp_c: Some(99.0),
            charging: Some(true),
            battery_pct: Some(40),
            ..Default::default()
        };
        let m = merge(a, b);
        assert_eq!(m.now_s, 5);
        assert_eq!(m.battery_temp_c, Some(30.0)); // el primario manda
        assert_eq!(m.charging, Some(true));
        assert_eq!(m.battery_pct, Some(40));
    }

    #[test]
    fn sysfs_source_reads_a_directory() {
        let dir = std::env::temp_dir().join(format!("armax-thermal-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("temp"), "385\n").unwrap();
        fs::write(dir.join("capacity"), "64\n").unwrap();
        fs::write(dir.join("status"), "Discharging\n").unwrap();
        let s = SysfsSource::with_base(&dir).read(7);
        assert_eq!(s.now_s, 7);
        assert_eq!(s.battery_temp_c, Some(38.5));
        assert_eq!(s.battery_pct, Some(64));
        assert_eq!(s.charging, Some(false));
        assert_eq!(s.screen_on, None);
        fs::remove_dir_all(&dir).ok();

        // directorio inexistente: todo desconocido (el gobernador pausará por seguridad)
        let s = SysfsSource::with_base("/no/existe").read(0);
        assert_eq!((s.battery_temp_c, s.charging, s.battery_pct), (None, None, None));
    }
}
