//! Un share: un bloque candidato completo (cabecera + coinbase) cuyo PoW cumple un umbral `ratio`
//! veces más fácil que el del bloque.
//!
//! Es un candidato de verdad: su coinbase ya reparte la recompensa entre los mineros recientes del
//! pool, y la cabecera compromete ese reparto (Merkle → coinbase → salidas). Si el digest además
//! cumple el target del bloque, el share **es** un bloque válido y se publica tal cual. Por eso
//! nadie puede apropiarse de un share ajeno cambiando la dirección de pago: cambiaría el id y
//! habría que rehacer el PoW.
//!
//! Puede llevar transacciones del mempool de quien lo halla (hasta `MAX_SHARE_TXS` y
//! `MAX_SHARE_TX_BYTES`): sus comisiones van al coinbase y se reparten entre los mineros de la
//! ventana igual que el subsidio. La sharechain no ejecuta esas transacciones (no tiene el estado
//! de cada rama): comprueba que la cabecera las compromete bien y que el reparto de montos
//! cuadra con las comisiones declaradas; la verdad de las comisiones la comprueba el libro mayor
//! cuando un share resulta ser un bloque. Un share con comisiones falsas no puede ser bloque, así
//! que solo desperdicia el trabajo de quien lo fabricó.

use armax_chain::block::{Block, Coinbase, MAX_COINBASE_EXTRA, MAX_COINBASE_OUTPUTS};
use armax_chain::Address;
use armax_keys::tx::Transaction;
use armax_pow::{BlockHeader, Hash32, HEADER_LEN};

/// Marca de versión del formato del share dentro de `coinbase.extra`.
pub const SHARE_MAGIC: &[u8; 7] = b"ARMXSH1";

/// `extra` = magic (7) | share anterior (32) | dirección del minero (32).
pub const EXTRA_LEN: usize = 7 + 32 + 32;
const _: () = assert!(EXTRA_LEN <= MAX_COINBASE_EXTRA);

/// Cota del coinbase serializado (8+8+1+64·44+1+100 = 2,934): rechaza basura antes de decodificar.
pub const MAX_COINBASE_BYTES: usize = 8 + 8 + 1 + MAX_COINBASE_OUTPUTS * 44 + 1 + MAX_COINBASE_EXTRA;

/// Transacciones por share. Los shares son frecuentes (uno cada pocos segundos) y se retransmiten
/// enteros, así que se mantienen mucho más pequeños que un bloque.
pub const MAX_SHARE_TXS: usize = 50;
/// Suma de los bytes serializados de las transacciones de un share.
pub const MAX_SHARE_TX_BYTES: usize = 64 * 1024;

/// Tamaño máximo de un share serializado.
pub const MAX_SHARE_BYTES: usize = HEADER_LEN + 4 + MAX_COINBASE_BYTES + 4 + MAX_SHARE_TXS * 4 + MAX_SHARE_TX_BYTES;

/// Identificador del "share anterior" del primero de la cadena.
pub const NO_PREV: Hash32 = [0u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShareMeta {
    /// Share anterior en la sharechain (`NO_PREV` si es el primero).
    pub prev_share: Hash32,
    /// Quien halló el share: cobra en los repartos que lo incluyan.
    pub miner: Address,
}

pub fn make_extra(prev_share: &Hash32, miner: &Address) -> Vec<u8> {
    let mut v = Vec::with_capacity(EXTRA_LEN);
    v.extend_from_slice(SHARE_MAGIC);
    v.extend_from_slice(prev_share);
    v.extend_from_slice(&miner.0);
    v
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    pub header: BlockHeader,
    pub coinbase: Coinbase,
    /// Transacciones (vacío en un share sin comisiones).
    pub txs: Vec<Transaction>,
}

impl Share {
    /// El id del share es el id de su cabecera (el del bloque que sería).
    pub fn id(&self) -> Hash32 {
        self.header.id()
    }

    /// Lee `prev_share` y `miner` de `coinbase.extra`; formato exacto.
    pub fn meta(&self) -> Option<ShareMeta> {
        let e = &self.coinbase.extra;
        if e.len() != EXTRA_LEN || &e[..7] != SHARE_MAGIC {
            return None;
        }
        Some(ShareMeta {
            prev_share: e[7..39].try_into().unwrap(),
            miner: Address(e[39..71].try_into().unwrap()),
        })
    }

    /// El bloque que este share sería si su PoW cumpliera el target del bloque.
    pub fn to_block(&self) -> Block {
        Block {
            header: self.header.clone(),
            coinbase: self.coinbase.clone(),
            tx_leaves: self.txs.iter().map(|t| t.full_id()).collect(),
        }
    }

    /// Bytes que ocupan sus transacciones serializadas.
    pub fn tx_bytes(&self) -> usize {
        self.txs.iter().map(|t| t.to_bytes().len()).sum()
    }

    /// Formato: `cabecera (124) | coinbase_len u32 LE | coinbase | n_txs u32 LE | n × (len u32 | tx)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let cb = self.coinbase.to_bytes();
        let mut b = Vec::with_capacity(HEADER_LEN + 8 + cb.len() + self.txs.len() * 300);
        b.extend_from_slice(&self.header.to_bytes());
        b.extend_from_slice(&(cb.len() as u32).to_le_bytes());
        b.extend_from_slice(&cb);
        b.extend_from_slice(&(self.txs.len() as u32).to_le_bytes());
        for t in &self.txs {
            let tb = t.to_bytes();
            b.extend_from_slice(&(tb.len() as u32).to_le_bytes());
            b.extend_from_slice(&tb);
        }
        b
    }

    /// Lectura estricta: sin bytes sobrantes y dentro de las cotas.
    pub fn from_bytes(data: &[u8]) -> Result<Share, &'static str> {
        if data.len() > MAX_SHARE_BYTES {
            return Err("share demasiado grande");
        }
        let mut pos = 0usize;
        let mut take = |n: usize| -> Result<&[u8], &'static str> {
            let end = pos.checked_add(n).ok_or("desbordamiento")?;
            let s = data.get(pos..end).ok_or("datos cortos")?;
            pos = end;
            Ok(s)
        };
        let header = BlockHeader::from_bytes(take(HEADER_LEN)?).map_err(|_| "cabecera inválida")?;
        let cb_len = u32::from_le_bytes(take(4)?.try_into().unwrap()) as usize;
        if cb_len > MAX_COINBASE_BYTES {
            return Err("coinbase demasiado grande");
        }
        let coinbase = Coinbase::from_bytes(take(cb_len)?)?;
        let n = u32::from_le_bytes(take(4)?.try_into().unwrap()) as usize;
        if n > MAX_SHARE_TXS {
            return Err("demasiadas transacciones");
        }
        let mut txs = Vec::with_capacity(n);
        let mut total = 0usize;
        for _ in 0..n {
            let l = u32::from_le_bytes(take(4)?.try_into().unwrap()) as usize;
            total = total.saturating_add(l);
            if total > MAX_SHARE_TX_BYTES {
                return Err("transacciones demasiado grandes");
            }
            txs.push(Transaction::from_bytes(take(l)?).map_err(|_| "transacción inválida")?);
        }
        if pos != data.len() {
            return Err("bytes sobrantes");
        }
        Ok(Share { header, coinbase, txs })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use armax_chain::block::genesis_block;
    use armax_chain::Output;

    fn sample() -> Share {
        let g = genesis_block(1_800_000_000, b"x");
        let coinbase = Coinbase {
            height: 1,
            fees: 0,
            outputs: vec![Output { address: Address([1; 32]), share_ppm: 1_000_000, amount: 5 }],
            extra: make_extra(&[9; 32], &Address([2; 32])),
        };
        let mut header = g.header.clone();
        header.height = 1;
        Share { header, coinbase, txs: vec![] }
    }

    #[test]
    fn roundtrip_meta_and_strictness() {
        let s = sample();
        let b = s.to_bytes();
        assert_eq!(Share::from_bytes(&b), Ok(s.clone()));
        let m = s.meta().unwrap();
        assert_eq!(m.prev_share, [9; 32]);
        assert_eq!(m.miner, Address([2; 32]));

        let mut longer = b.clone();
        longer.push(0);
        assert!(Share::from_bytes(&longer).is_err());
        for cut in 0..b.len() {
            assert!(Share::from_bytes(&b[..cut]).is_err(), "cut={cut}");
        }
        assert!(Share::from_bytes(&vec![0u8; MAX_SHARE_BYTES + 1]).is_err());
    }

    #[test]
    fn meta_is_exact() {
        let mut s = sample();
        s.coinbase.extra.push(0);
        assert!(s.meta().is_none(), "bytes sobrantes");
        let mut s = sample();
        s.coinbase.extra[0] ^= 1;
        assert!(s.meta().is_none(), "magic distinto");
        let mut s = sample();
        s.coinbase.extra.clear();
        assert!(s.meta().is_none());
    }

    #[test]
    fn id_covers_the_payout_commitment() {
        // el id sale de la cabecera: cambiar la dirección de pago exige rehacer la raíz de Merkle
        // y, con ella, el PoW; aquí basta ver que la raíz depende del coinbase.
        let a = sample();
        let mut b = sample();
        b.coinbase.outputs[0].address = Address([3; 32]);
        let leaves = |s: &Share| armax_chain::merkle::merkle_root(&[s.coinbase.id()]);
        assert_ne!(leaves(&a), leaves(&b));
    }
}
