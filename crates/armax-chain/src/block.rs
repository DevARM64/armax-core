//! Coinbase y bloque.
//!
//! El coinbase puede pagar a varias direcciones (hasta 64), para que un pool descentralizado
//! reparta la recompensa sin custodiar fondos; el reparto es voluntario: el consenso solo
//! comprueba su forma y que el amortiguador por dirección se aplique a cada parte.
//!
//! Por ahora el cuerpo de un bloque es solo el coinbase (aún no hay transacciones de usuario:
//! el modelo de cuentas/UTXO y las firmas vienen con `armax-keys`/`armax-ledger`). La raíz de
//! Merkle ya cubre una lista de hojas, así que añadir transacciones no cambia el formato.

use armax_pow::consensus::{initial_target, HEADER_VERSION};
use armax_pow::{BlockHeader, Hash32};
use armax_vm::sha256::sha256_cat;

use crate::merkle::merkle_root;
use crate::types::Address;

pub const MAX_COINBASE_EXTRA: usize = 100;

/// Máximo de transacciones (además del coinbase) por bloque.
pub const MAX_BLOCK_TXS: usize = 1_000;

/// Máximo de salidas (direcciones distintas) por coinbase.
pub const MAX_COINBASE_OUTPUTS: usize = 64;

/// Las partes (`share_ppm`) de un coinbase suman exactamente esto (partes por millón).
pub const SHARE_TOTAL: u32 = 1_000_000;

/// Parte mínima por salida (0.1 %): evita llenar el coinbase de pagos diminutos. Quien arma el
/// reparto (p. ej. un sharechain) debe sumar lo que quede por debajo de este mínimo a otras salidas.
pub const MIN_SHARE_PPM: u32 = 1_000;

/// Una salida del coinbase.
/// * `share_ppm`: parte del bloque que le corresponde a la dirección, antes del amortiguador.
/// * `amount`: lo que realmente cobra, en unidades: `subsidio · share_ppm / 1e6` ya amortiguado.
///   El consenso lo recalcula y exige que coincida exactamente.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Output {
    pub address: Address,
    pub share_ppm: u32,
    pub amount: u64,
}

/// Transacción de emisión. Formato canónico:
/// `height u64 LE | fees u64 LE | n u8 | n × (address 32 | share_ppm u32 LE | amount u64 LE) | extra_len u8 | extra`.
/// El génesis no tiene salidas (no emite ni paga a nadie).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coinbase {
    pub height: u64,
    /// Comisiones totales de las transacciones del bloque (entradas − salidas). Este crate no ve
    /// las transacciones: el libro mayor (`armax-ledger`) comprueba que el valor sea el real.
    /// Se reparten entre las salidas según su parte, **sin** pasar por el amortiguador (el tope
    /// limita la emisión, no lo que pagan los usuarios).
    pub fees: u64,
    pub outputs: Vec<Output>,
    pub extra: Vec<u8>,
}

impl Coinbase {
    /// Total emitido por este bloque (suma de las salidas).
    pub fn reward(&self) -> u64 {
        self.outputs.iter().map(|o| o.amount).sum()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        assert!(self.extra.len() <= MAX_COINBASE_EXTRA);
        assert!(self.outputs.len() <= MAX_COINBASE_OUTPUTS);
        let mut b = Vec::with_capacity(8 + 8 + 1 + self.outputs.len() * 44 + 1 + self.extra.len());
        b.extend_from_slice(&self.height.to_le_bytes());
        b.extend_from_slice(&self.fees.to_le_bytes());
        b.push(self.outputs.len() as u8);
        for o in &self.outputs {
            b.extend_from_slice(&o.address.0);
            b.extend_from_slice(&o.share_ppm.to_le_bytes());
            b.extend_from_slice(&o.amount.to_le_bytes());
        }
        b.push(self.extra.len() as u8);
        b.extend_from_slice(&self.extra);
        b
    }

    /// Lectura estricta del formato canónico: sin bytes sobrantes y dentro de los límites.
    pub fn from_bytes(data: &[u8]) -> Result<Coinbase, &'static str> {
        let mut pos = 0usize;
        let mut take = |n: usize| -> Result<&[u8], &'static str> {
            let end = pos.checked_add(n).ok_or("desbordamiento")?;
            let s = data.get(pos..end).ok_or("datos cortos")?;
            pos = end;
            Ok(s)
        };
        let height = u64::from_le_bytes(take(8)?.try_into().unwrap());
        let fees = u64::from_le_bytes(take(8)?.try_into().unwrap());
        let n = take(1)?[0] as usize;
        if n > MAX_COINBASE_OUTPUTS {
            return Err("demasiadas salidas");
        }
        let mut outputs = Vec::with_capacity(n);
        for _ in 0..n {
            let raw = take(44)?;
            outputs.push(Output {
                address: Address(raw[..32].try_into().unwrap()),
                share_ppm: u32::from_le_bytes(raw[32..36].try_into().unwrap()),
                amount: u64::from_le_bytes(raw[36..44].try_into().unwrap()),
            });
        }
        let extra_len = take(1)?[0] as usize;
        if extra_len > MAX_COINBASE_EXTRA {
            return Err("extra demasiado largo");
        }
        let extra = take(extra_len)?.to_vec();
        if pos != data.len() {
            return Err("bytes sobrantes");
        }
        Ok(Coinbase { height, fees, outputs, extra })
    }

    pub fn id(&self) -> Hash32 {
        sha256_cat(&[b"ARMAX-COINBASE-v2", &self.to_bytes()])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub coinbase: Coinbase,
    /// Identificadores completos (`full_id`) de las transacciones del bloque, en orden. Este
    /// crate solo los usa para la raíz de Merkle; las transacciones las valida `armax-ledger`.
    pub tx_leaves: Vec<Hash32>,
}

impl Block {
    pub fn id(&self) -> Hash32 {
        self.header.id()
    }

    /// Raíz de Merkle que debe declarar la cabecera.
    pub fn expected_merkle_root(&self) -> Hash32 {
        let mut leaves = Vec::with_capacity(1 + self.tx_leaves.len());
        leaves.push(self.coinbase.id());
        leaves.extend_from_slice(&self.tx_leaves);
        merkle_root(&leaves)
    }
}

/// Bloque génesis: sin recompensa, sin dirección, sin PoW. Solo lleva un mensaje y la hora
/// de lanzamiento. Su id es una constante de consenso que se publica junto al binario.
pub fn genesis_block(timestamp: u64, message: &[u8]) -> Block {
    let coinbase = Coinbase { height: 0, fees: 0, outputs: vec![], extra: message.to_vec() };
    let header = BlockHeader {
        version: HEADER_VERSION,
        height: 0,
        prev_hash: [0u8; 32],
        merkle_root: merkle_root(&[coinbase.id()]),
        timestamp,
        target: initial_target(),
        nonce: 0,
    };
    Block { header, coinbase, tx_leaves: vec![] }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Coinbase {
        Coinbase {
            height: 5,
            fees: 7,
            outputs: vec![
                Output { address: Address([1; 32]), share_ppm: 600_000, amount: 60 },
                Output { address: Address([2; 32]), share_ppm: 400_000, amount: 40 },
            ],
            extra: vec![9],
        }
    }

    #[test]
    fn coinbase_id_covers_every_field() {
        let base = sample();
        let mut v = vec![];
        let mut c = base.clone();
        c.height += 1;
        v.push(c);
        let mut c = base.clone();
        c.fees += 1;
        v.push(c);
        let mut c = base.clone();
        c.outputs[0].address.0[0] ^= 1;
        v.push(c);
        let mut c = base.clone();
        c.outputs[1].amount += 1;
        v.push(c);
        let mut c = base.clone();
        c.outputs[1].share_ppm -= 1;
        v.push(c);
        let mut c = base.clone();
        c.outputs.swap(0, 1); // el orden de las salidas importa
        v.push(c);
        let mut c = base.clone();
        c.outputs.pop();
        v.push(c);
        let mut c = base.clone();
        c.extra.push(0);
        v.push(c);
        for c in v {
            assert_ne!(c.id(), base.id());
        }
    }

    #[test]
    fn reward_is_the_sum_of_outputs_and_encoding_is_canonical() {
        let c = sample();
        assert_eq!(c.reward(), 100);
        let b = c.to_bytes();
        assert_eq!(b.len(), 8 + 8 + 1 + 2 * 44 + 1 + 1);
        assert_eq!(&b[8..16], &7u64.to_le_bytes()); // comisiones
        assert_eq!(b[16], 2); // número de salidas
        assert_eq!(&b[17..49], &[1u8; 32]);
        assert_eq!(&b[49..53], &600_000u32.to_le_bytes());
        assert_eq!(&b[53..61], &60u64.to_le_bytes());
        assert_eq!(Coinbase { height: 0, fees: 0, outputs: vec![], extra: vec![] }.reward(), 0);
    }

    #[test]
    fn share_constants_are_consistent() {
        assert!(MIN_SHARE_PPM as usize * MAX_COINBASE_OUTPUTS <= SHARE_TOTAL as usize);
        assert!(MAX_COINBASE_OUTPUTS <= u8::MAX as usize);
    }

    #[test]
    fn merkle_root_commits_to_every_transaction_leaf() {
        let g = genesis_block(1_800_000_000, b"m");
        let mut b = g.clone();
        let base = b.expected_merkle_root();
        b.tx_leaves.push([1u8; 32]);
        let one = b.expected_merkle_root();
        assert_ne!(base, one);
        b.tx_leaves.push([2u8; 32]);
        let two = b.expected_merkle_root();
        assert_ne!(one, two);
        b.tx_leaves.swap(0, 1);
        assert_ne!(two, b.expected_merkle_root(), "el orden de las transacciones importa");
    }

    #[test]
    fn genesis_is_well_formed_and_deterministic() {
        let g = genesis_block(1_800_000_000, b"mensaje del genesis");
        assert_eq!(g.header.height, 0);
        assert!(g.coinbase.outputs.is_empty());
        assert_eq!(g.header.merkle_root, g.expected_merkle_root());
        assert_eq!(g.id(), genesis_block(1_800_000_000, b"mensaje del genesis").id());
        assert_ne!(g.id(), genesis_block(1_800_000_001, b"mensaje del genesis").id());
    }

    #[test]
    fn coinbase_bytes_roundtrip_and_strict() {
        let cb = Coinbase {
            height: 7,
            fees: 99,
            outputs: vec![
                Output { address: Address([1; 32]), share_ppm: 600_000, amount: 5 },
                Output { address: Address([2; 32]), share_ppm: 400_000, amount: 3 },
            ],
            extra: b"hola".to_vec(),
        };
        let b = cb.to_bytes();
        assert_eq!(Coinbase::from_bytes(&b), Ok(cb.clone()));
        let mut longer = b.clone();
        longer.push(0);
        assert!(Coinbase::from_bytes(&longer).is_err());
        for cut in 0..b.len() {
            assert!(Coinbase::from_bytes(&b[..cut]).is_err(), "cut={cut}");
        }
    }
}
