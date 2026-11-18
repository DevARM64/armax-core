//! Scratchpad de minería y comprobaciones de memoria.
//!
//! Esta versión usa `Vec` con reserva fallible (no aborta si no hay memoria).
//! La variante de Android con `mmap(MAP_ANONYMOUS|MAP_NORESERVE)` y `madvise`
//! requiere el crate `libc` y va en `armax-node` cuando se puedan traer
//! dependencias; la interfaz (`Scratchpad::as_mut_slice`) no cambia.

use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum MemError {
    /// El sistema rechazó la reserva de `bytes`.
    Alloc(usize),
    /// `MemAvailable` no alcanza para `need` bytes más la holgura pedida.
    Insufficient { need: u64, available: u64 },
}

impl fmt::Display for MemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemError::Alloc(b) => write!(f, "no se pudo reservar {b} bytes"),
            MemError::Insufficient { need, available } => {
                write!(f, "memoria insuficiente: se necesitan {need} B y hay {available} B disponibles")
            }
        }
    }
}

impl std::error::Error for MemError {}

/// Bytes de `MemAvailable` según `/proc/meminfo` (Linux/Android). `None` si no se puede leer.
pub fn mem_available_bytes() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    parse_mem_available(&text)
}

fn parse_mem_available(text: &str) -> Option<u64> {
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemAvailable:") {
            let kb: u64 = rest.trim().trim_end_matches("kB").trim().parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

/// Comprueba que hay `bytes + headroom` disponibles antes de intentar asignar.
/// Si no se puede leer `/proc/meminfo`, deja pasar (la reserva fallible decide).
pub fn check_memory(bytes: usize, headroom: usize) -> Result<(), MemError> {
    if let Some(avail) = mem_available_bytes() {
        let need = bytes as u64 + headroom as u64;
        if avail < need {
            return Err(MemError::Insufficient { need, available: avail });
        }
    }
    Ok(())
}

pub struct Scratchpad {
    buf: Vec<u8>,
}

impl Scratchpad {
    pub fn new(bytes: usize) -> Result<Self, MemError> {
        let mut buf = Vec::new();
        buf.try_reserve_exact(bytes).map_err(|_| MemError::Alloc(bytes))?;
        buf.resize(bytes, 0);
        Ok(Self { buf })
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_meminfo() {
        let t = "MemTotal:        8000000 kB\nMemAvailable:    3145728 kB\nBuffers: 1 kB\n";
        assert_eq!(parse_mem_available(t), Some(3145728 * 1024));
        assert_eq!(parse_mem_available("nada"), None);
    }

    #[test]
    fn allocates_and_rejects_absurd_sizes() {
        let mut s = Scratchpad::new(1 << 20).unwrap();
        assert_eq!(s.len(), 1 << 20);
        assert!(s.as_mut_slice().iter().all(|&b| b == 0));
        assert!(Scratchpad::new(usize::MAX / 2).is_err());
    }

    #[test]
    fn insufficient_memory_is_reported() {
        if mem_available_bytes().is_some() {
            let err = check_memory(usize::MAX / 4, 0).unwrap_err();
            assert!(matches!(err, MemError::Insufficient { .. }));
        }
    }
}
