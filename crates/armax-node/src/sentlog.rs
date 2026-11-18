//! Registro de las comisiones de los envíos hechos desde este nodo.
//!
//! Una vez confirmada una transacción, sus entradas ya no están en el conjunto UTXO y reconstruir
//! la comisión obligaría a recorrer la cadena. Por eso `send` anota `txid comisión` en
//! `DATA/sent.log` (un renglón por envío) y el historial lo consulta. Un envío hecho desde otro
//! dispositivo con la misma cartera no aparece aquí y se muestra sin comisión.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

/// Máximo de renglones que se leen (los más recientes).
const MAX_LINES: usize = 20_000;

#[derive(Clone, Debug)]
pub struct SentLog {
    path: PathBuf,
}

impl SentLog {
    pub fn new(path: PathBuf) -> SentLog {
        SentLog { path }
    }

    /// Anota un envío. Los errores de disco se ignoran: es información de comodidad.
    pub fn record(&self, txid: &[u8; 32], fee: u64) {
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&self.path) {
            let _ = writeln!(f, "{} {}", hex(txid), fee);
        }
    }

    pub fn load(&self) -> HashMap<[u8; 32], u64> {
        let mut m = HashMap::new();
        let Ok(text) = fs::read_to_string(&self.path) else { return m };
        let lines: Vec<&str> = text.lines().collect();
        let start = lines.len().saturating_sub(MAX_LINES);
        for line in &lines[start..] {
            let mut it = line.split_whitespace();
            let (Some(h), Some(f)) = (it.next(), it.next()) else { continue };
            if let (Some(id), Ok(fee)) = (unhex(h), f.parse::<u64>()) {
                m.insert(id, fee);
            }
        }
        m
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_reloads_fees_and_ignores_garbage() {
        let dir = std::env::temp_dir().join(format!("armax-sentlog-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let log = SentLog::new(dir.join("sent.log"));
        assert!(log.load().is_empty());
        log.record(&[1; 32], 10_000);
        log.record(&[2; 32], 0);
        fs::OpenOptions::new().append(true).open(dir.join("sent.log")).unwrap().write_all(b"basura\nzz 5\n\n").unwrap();
        log.record(&[1; 32], 12_345); // el último gana
        let m = log.load();
        assert_eq!(m.len(), 2);
        assert_eq!(m[&[1; 32]], 12_345);
        assert_eq!(m[&[2; 32]], 0);
        let _ = fs::remove_dir_all(&dir);
    }
}
