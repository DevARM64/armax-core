//! Redes. Cada una tiene su propio génesis, así que sus nodos no se mezclan.

use armax_chain::block::{genesis_block, Block};
use armax_vm::Params;

/// Fecha fija en el pasado (22-sep-2026): los bloques nuevos nunca quedan "en el futuro".
pub const DEVNET_GENESIS_TIME: u64 = 1_790_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    /// PoW reducido (`Params::TEST`, ~3 ms por intento): para probar la mecánica en segundos.
    Fast,
    /// Parámetros de consenso (384 MiB por hilo, ~5 H/s en un teléfono): el comportamiento real.
    Devnet,
}

impl Network {
    pub fn parse(s: &str) -> Option<Network> {
        match s {
            "fast" => Some(Network::Fast),
            "devnet" => Some(Network::Devnet),
            _ => None,
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            Network::Fast => "fast",
            Network::Devnet => "devnet",
        }
    }
    pub fn params(&self) -> Params {
        match self {
            Network::Fast => Params::TEST,
            Network::Devnet => Params::CONSENSUS,
        }
    }
    /// Bloques que deben pasar antes de gastar una recompensa. En `fast` es corto para poder
    /// probar pagos en minutos; en `devnet` es el valor de consenso.
    pub fn coinbase_maturity(&self) -> u64 {
        match self {
            Network::Fast => 3,
            Network::Devnet => armax_keys::utxo::COINBASE_MATURITY,
        }
    }
    /// Parámetros de la sharechain (P2Pool). En `fast` la ventana y la razón son pequeñas para ver
    /// el reparto en minutos.
    pub fn share_params(&self) -> armax_share::ShareParams {
        match self {
            Network::Fast => armax_share::ShareParams::FAST,
            Network::Devnet => armax_share::ShareParams::MAINNET,
        }
    }
    pub fn genesis(&self) -> Block {
        let msg: &[u8] = match self {
            Network::Fast => b"ARMax fast devnet",
            Network::Devnet => b"ARMax devnet",
        };
        genesis_block(DEVNET_GENESIS_TIME, msg)
    }
}
