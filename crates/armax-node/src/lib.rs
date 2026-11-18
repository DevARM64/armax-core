//! `armax-node`: el nodo completo como biblioteca (y el binario `armax-node` encima).
//!
//! * `network`: redes disponibles (`fast` para pruebas, `devnet` con los parámetros de consenso).
//! * `walletfile`: archivo de cartera **de desarrollo** (`InsecureTestVault`).
//! * `pay`: selección de monedas y construcción de pagos.
//! * `miner`: hilos de minado gobernados por el gobernador térmico.
//! * `app`: arranque y operación del nodo.
//! * `history`: historial de la cartera (minado, recibido, enviado).

pub mod app;
pub mod history;
pub mod miner;
pub mod network;
pub mod pay;
pub mod sentlog;
pub mod walletfile;

/// 1 ARM = 100,000,000 unidades.
pub const COIN: u64 = armax_chain::COIN;

/// "12.5" → unidades. Estricto: hasta 8 decimales, sin signos ni espacios.
pub fn parse_amount(s: &str) -> Result<u64, String> {
    let (int, frac) = match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s, ""),
    };
    if int.is_empty() && frac.is_empty() || !int.chars().all(|c| c.is_ascii_digit()) || !frac.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("cantidad inválida: {s:?}"));
    }
    if frac.len() > 8 {
        return Err("máximo 8 decimales".into());
    }
    let i: u64 = if int.is_empty() { 0 } else { int.parse().map_err(|_| "cantidad demasiado grande".to_string())? };
    let f: u64 = if frac.is_empty() { 0 } else { format!("{frac:0<8}").parse().unwrap() };
    i.checked_mul(COIN).and_then(|v| v.checked_add(f)).ok_or_else(|| "cantidad demasiado grande".to_string())
}

pub fn format_amount(units: u128) -> String {
    format!("{}.{:08}", units / COIN as u128, units % COIN as u128)
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts_parse_and_print() {
        assert_eq!(parse_amount("12.5"), Ok(1_250_000_000));
        assert_eq!(parse_amount("0.00000001"), Ok(1));
        assert_eq!(parse_amount("3"), Ok(300_000_000));
        assert_eq!(parse_amount(".5"), Ok(50_000_000));
        for bad in ["", ".", "-1", "1.123456789", "1,5", " 1", "1e3", "99999999999999999999"] {
            assert!(parse_amount(bad).is_err(), "{bad:?}");
        }
        assert_eq!(format_amount(1_250_000_000), "12.50000000");
        assert_eq!(format_amount(1), "0.00000001");
    }

    #[test]
    fn hex_roundtrip() {
        let b = [0u8, 1, 0xab, 0xff];
        assert_eq!(unhex(&hex(&b)), Some(b.to_vec()));
        assert_eq!(unhex("abc"), None);
        assert_eq!(unhex("zz"), None);
    }
}
