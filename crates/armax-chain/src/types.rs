//! Tipos básicos: direcciones y cantidades.

use core::fmt;

/// 1 ARM = 10^8 unidades mínimas. Todas las cantidades de consenso son `u64` en unidades.
pub const COIN: u64 = 100_000_000;

/// Dirección de 32 bytes (más adelante: hash de la clave pública Ed25519 de `armax-keys`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Address(pub [u8; 32]);

impl Address {
    pub const ZERO: Address = Address([0u8; 32]);
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0[..6] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "…")
    }
}
