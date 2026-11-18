//! Redes. Cada una tiene su propio génesis, así que sus nodos no se mezclan.

use armax_chain::block::{genesis_block, Block};
use armax_vm::Params;

/// Fecha fija en el pasado (22-sep-2026): los bloques nuevos nunca quedan "en el futuro".
pub const DEVNET_GENESIS_TIME: u64 = 1_790_000_000;

/// Génesis de la testnet pública (6-nov-2026 21:20 UTC): también en el pasado.
pub const TESTNET_GENESIS_TIME: u64 = 1_794_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    /// PoW reducido (`Params::TEST`, ~3 ms por intento): para probar la mecánica en segundos.
    Fast,
    /// Parámetros de consenso (384 MiB por hilo, ~5 H/s en un teléfono): el comportamiento real.
    Devnet,
    /// Testnet pública: parámetros reales como `Devnet` (384 MiB por hilo, madurez 100) pero con su
    /// propio génesis, para empezar de cero y no mezclarse con las pruebas anteriores.
    Testnet,
}

impl Network {
    pub fn parse(s: &str) -> Option<Network> {
        match s {
            "fast" => Some(Network::Fast),
            "devnet" => Some(Network::Devnet),
            "testnet" => Some(Network::Testnet),
            _ => None,
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            Network::Fast => "fast",
            Network::Devnet => "devnet",
            Network::Testnet => "testnet",
        }
    }
    pub fn params(&self) -> Params {
        match self {
            Network::Fast => Params::TEST,
            Network::Devnet | Network::Testnet => Params::CONSENSUS,
        }
    }
    /// Bloques que deben pasar antes de gastar una recompensa. En `fast` es corto para poder
    /// probar pagos en minutos; en `devnet` es el valor de consenso.
    pub fn coinbase_maturity(&self) -> u64 {
        match self {
            Network::Fast => 3,
            Network::Devnet | Network::Testnet => armax_keys::utxo::COINBASE_MATURITY,
        }
    }
    /// Parámetros de la sharechain (P2Pool). En `fast` la ventana y la razón son pequeñas para ver
    /// el reparto en minutos.
    pub fn share_params(&self) -> armax_share::ShareParams {
        match self {
            Network::Fast => armax_share::ShareParams::FAST,
            Network::Devnet | Network::Testnet => armax_share::ShareParams::MAINNET,
        }
    }
    pub fn genesis(&self) -> Block {
        let (time, msg): (u64, &[u8]) = match self {
            Network::Fast => (DEVNET_GENESIS_TIME, b"ARMax fast devnet"),
            Network::Devnet => (DEVNET_GENESIS_TIME, b"ARMax devnet"),
            Network::Testnet => (TESTNET_GENESIS_TIME, b"ARMax testnet 1"),
        };
        genesis_block(time, msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_name_round_trip() {
        for n in [Network::Fast, Network::Devnet, Network::Testnet] {
            assert_eq!(Network::parse(n.name()), Some(n));
        }
        assert_eq!(Network::parse("mainnet"), None);
    }

    #[test]
    fn every_network_has_its_own_genesis() {
        let ids: Vec<_> = [Network::Fast, Network::Devnet, Network::Testnet].iter().map(|n| n.genesis().id()).collect();
        assert_ne!(ids[0], ids[1]);
        assert_ne!(ids[0], ids[2]);
        assert_ne!(ids[1], ids[2]);
    }

    #[test]
    fn testnet_uses_real_consensus_parameters() {
        let t = Network::Testnet;
        let d = Network::Devnet;
        assert_eq!(t.coinbase_maturity(), armax_keys::utxo::COINBASE_MATURITY);
        assert_eq!(t.coinbase_maturity(), d.coinbase_maturity());
        assert_eq!(t.share_params(), d.share_params());
        assert_eq!(t.params().iterations, armax_vm::Params::CONSENSUS.iterations);
        assert!(TESTNET_GENESIS_TIME > DEVNET_GENESIS_TIME);
    }
}
