//! La cadena de shares: validación, elección de la mejor punta y plantillas para minar.
//!
//! # Reglas de un share (todas deterministas; el pool es voluntario, el consenso de bloques no cambia)
//! 1. `coinbase.extra` con el formato exacto (magic, share anterior, minero).
//! 2. Cuerpo: altura del coinbase = altura de la cabecera; raíz de Merkle = la del coinbase más
//!    las transacciones del share (a lo sumo `MAX_SHARE_TXS`, sin repetidas); sin transacciones no
//!    hay comisiones. Las comisiones declaradas no se comprueban aquí (no hay estado de UTXO por
//!    rama): las verifica el libro mayor si el share llega a ser bloque.
//! 3. El share anterior existe (o es `NO_PREV`) y el bloque padre es conocido: si falta alguno, el
//!    share es **huérfano** (`is_orphan`): la red lo retiene y pide lo que falta, sin castigar.
//! 4. Cabecera: versión, altura, enlace, **target exacto de LWMA**, mediana de tiempo y límite de
//!    futuro, igual que un bloque.
//! 5. La altura de bloque nunca retrocede a lo largo de la sharechain (`header.height ≥` la del
//!    share anterior). Es lo que impide acumular shares sobre un padre viejo para cobrar sin aportar
//!    trabajo útil: un share solo puede ser tan rancio como el último que ya estaba en la punta.
//! 6. **Reparto**: las salidas (dirección, parte) son exactamente `payout` de la ventana de shares
//!    que acaba en el share anterior más este, y los **montos** son los que el consenso exige tras
//!    el amortiguador. Así un share con montos inventados (que jamás podría ser bloque) no cobra.
//! 7. **PoW** con la semilla de época, contra `target·ratio` (más fácil que el del bloque).
//!
//! El orden es el de los bloques: lo barato primero, la VM al final.
//!
//! # Peso y ventana
//! Cada share pesa el trabajo esperado de su umbral (`block_work(target·ratio)`), así que si la
//! dificultad cambia, los shares viejos valen lo que costaron. La ventana son los últimos
//! `ShareParams::window` shares de la rama. La mejor punta es la de mayor peso acumulado (empate: la
//! primera vista).

use std::collections::HashMap;

use armax_chain::block::Block;
use armax_chain::merkle::merkle_root;
use armax_chain::{Address, Chain, ChainError, SharePowCheck};
use armax_pow::consensus::pow_limit;
use armax_pow::{block_work, meets_target, next_target, validate_header_cheap, Hash32, HeaderError, U256};

use crate::payout::payout;
use crate::share::{make_extra, Share, MAX_SHARE_TXS, MAX_SHARE_TX_BYTES, NO_PREV};
use armax_keys::tx::Transaction;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShareParams {
    /// Cuántas veces más fácil que el bloque es el umbral de un share.
    pub ratio: u64,
    /// Shares de la ventana de reparto (incluido el que se está construyendo).
    pub window: usize,
}

impl ShareParams {
    /// Valores PROVISIONALES. Con bloques de 300 s, `ratio = 16` da un share cada ~19 s si todo el
    /// hashrate de la red estuviera en el pool; la ventana de 4,320 shares son ~270 bloques (~22 h).
    pub const MAINNET: ShareParams = ShareParams { ratio: 16, window: 4_320 };
    /// Para la red de pruebas `fast`.
    pub const FAST: ShareParams = ShareParams { ratio: 4, window: 256 };
}

/// Umbral de un share: `target·ratio`, sin pasar del límite de PoW.
pub fn share_target(block_target: &U256, ratio: u64) -> U256 {
    let t = block_target.mul_div_u64(ratio, 1).unwrap_or_else(pow_limit);
    if t > pow_limit() {
        pow_limit()
    } else {
        t
    }
}

/// Peso de un share: trabajo esperado de su umbral (≥ 1; satura en `u64::MAX`).
pub fn share_weight(block_target: &U256, ratio: u64) -> u64 {
    let w = block_work(&share_target(block_target, ratio));
    if w.0[1] != 0 || w.0[2] != 0 || w.0[3] != 0 {
        u64::MAX
    } else {
        w.0[0].max(1)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ShareError {
    BadExtra,
    BadCoinbase(&'static str),
    BadMerkleRoot,
    /// El share anterior no se conoce (huérfano: pedirlo).
    UnknownPrevShare,
    /// El bloque padre no se conoce o es inválido (huérfano: pedirlo).
    UnknownParent,
    /// Altura de bloque menor que la del share anterior.
    ParentRegresses,
    Header(HeaderError),
    /// Salidas o montos que no son los que dicta la regla de reparto.
    BadPayout(&'static str),
    Chain(ChainError),
    /// Transacciones incoherentes con la cabecera o fuera de las cotas.
    BadTxs(&'static str),
}

impl ShareError {
    /// ¿Falta información que quizá llegue después? (no es culpa del par).
    pub fn is_orphan(&self) -> bool {
        matches!(self, ShareError::UnknownPrevShare | ShareError::UnknownParent)
    }
}

impl From<HeaderError> for ShareError {
    fn from(e: HeaderError) -> Self {
        ShareError::Header(e)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AddShare {
    AlreadyKnown,
    Added {
        /// Es la nueva mejor punta de la sharechain.
        new_tip: bool,
        /// Su digest cumple también el target del bloque: `share.to_block()` es un bloque válido.
        is_block: bool,
    },
}

struct Entry {
    share: Share,
    miner: Address,
    prev: Hash32,
    weight: u64,
    /// Posición en la sharechain (el primero es 1).
    height: u64,
    cum: u128,
    /// ¿La cadena llega hasta el primer share (`NO_PREV`)? Falso si arrancó en un horizonte.
    rooted: bool,
    /// Shares desde el primero conservado (o desde la base de arranque), contando este.
    depth: u64,
}

pub struct ShareChain {
    params: ShareParams,
    entries: HashMap<Hash32, Entry>,
    tip: Option<Hash32>,
}

impl ShareChain {
    pub fn new(params: ShareParams) -> Self {
        ShareChain { params, entries: HashMap::new(), tip: None }
    }

    pub fn params(&self) -> &ShareParams {
        &self.params
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(&self, id: &Hash32) -> bool {
        self.entries.contains_key(id)
    }

    pub fn get(&self, id: &Hash32) -> Option<&Share> {
        self.entries.get(id).map(|e| &e.share)
    }

    /// Todos los shares conservados, cada padre antes que sus hijos (por posición y luego por id).
    pub fn shares_in_order(&self) -> Vec<&Share> {
        let mut v: Vec<(&Hash32, &Entry)> = self.entries.iter().collect();
        v.sort_by(|a, b| (a.1.height, a.0).cmp(&(b.1.height, b.0)));
        v.into_iter().map(|(_, e)| &e.share).collect()
    }

    /// Mejor punta (mayor peso acumulado), si hay shares.
    pub fn tip(&self) -> Option<Hash32> {
        self.tip
    }

    /// Posición del share `id` en la sharechain (1 = el primero).
    pub fn height_of(&self, id: &Hash32) -> Option<u64> {
        self.entries.get(id).map(|e| e.height)
    }

    /// Hasta `n` ids desde `from` hacia atrás (el más reciente primero).
    pub fn ids_back(&self, from: &Hash32, n: usize) -> Vec<Hash32> {
        let mut out = vec![];
        let mut cur = *from;
        while out.len() < n {
            let Some(e) = self.entries.get(&cur) else { break };
            out.push(cur);
            if e.prev == NO_PREV {
                break;
            }
            cur = e.prev;
        }
        out
    }

    /// Pesos (minero, peso) de hasta `n` shares desde `prev` hacia atrás.
    fn window_weights(&self, prev: Option<Hash32>, n: usize) -> Vec<(Address, u64)> {
        let mut out = Vec::with_capacity(n.min(8192));
        let mut cur = prev;
        while out.len() < n {
            let Some(id) = cur else { break };
            let Some(e) = self.entries.get(&id) else { break };
            out.push((e.miner, e.weight));
            cur = if e.prev == NO_PREV { None } else { Some(e.prev) };
        }
        out
    }

    /// Reparto del coinbase de un share nuevo de `miner` (peso `weight`) que cuelga de `prev`.
    pub fn next_payout(&self, prev: Option<Hash32>, miner: Address, weight: u64) -> Vec<(Address, u32)> {
        let mut w = self.window_weights(prev, self.params.window.saturating_sub(1));
        w.push((miner, weight));
        payout(&w, &prev.unwrap_or(NO_PREV))
    }

    /// Parte (ppm) que `miner` tiene en la ventana actual, contando desde la mejor punta: lo que
    /// cobraría en el siguiente reparto sin tener en cuenta su propio share nuevo ni el polvo.
    pub fn miner_ppm(&self, miner: &Address) -> u32 {
        let w = self.window_weights(self.tip, self.params.window);
        let total: u128 = w.iter().map(|x| x.1 as u128).sum();
        if total == 0 {
            return 0;
        }
        let mine: u128 = w.iter().filter(|x| x.0 == *miner).map(|x| x.1 as u128).sum();
        (mine * 1_000_000 / total) as u32
    }

    /// Valida un share y, si es correcto, lo incorpora.
    pub fn add(
        &mut self,
        share: Share,
        chain: &Chain,
        now: u64,
        pow: &mut dyn SharePowCheck,
    ) -> Result<AddShare, ShareError> {
        self.add_inner(share, chain, now, pow, false)
    }

    /// Arranque en el horizonte de un par: si la sharechain está **vacía**, admite como primer
    /// share uno cuyo anterior no conocemos (el par ya podó su historia). Su reparto, y el de los
    /// siguientes mientras su ventana no esté completa, no se puede comprobar (falta historia);
    /// todo lo demás (enlaces, cabecera, PoW) sí. Pasada una ventana, la validación es la normal.
    /// Con la sharechain no vacía se comporta como `add`.
    pub fn add_base(
        &mut self,
        share: Share,
        chain: &Chain,
        now: u64,
        pow: &mut dyn SharePowCheck,
    ) -> Result<AddShare, ShareError> {
        self.add_inner(share, chain, now, pow, true)
    }

    fn add_inner(
        &mut self,
        share: Share,
        chain: &Chain,
        now: u64,
        pow: &mut dyn SharePowCheck,
        base: bool,
    ) -> Result<AddShare, ShareError> {
        let id = share.id();
        if self.entries.contains_key(&id) {
            return Ok(AddShare::AlreadyKnown);
        }
        let meta = share.meta().ok_or(ShareError::BadExtra)?;
        let (h, cb) = (&share.header, &share.coinbase);

        // 2. cuerpo
        if cb.height != h.height {
            return Err(ShareError::BadCoinbase("altura del coinbase"));
        }
        if share.txs.len() > MAX_SHARE_TXS {
            return Err(ShareError::BadTxs("demasiadas transacciones"));
        }
        if share.txs.is_empty() && cb.fees != 0 {
            return Err(ShareError::BadCoinbase("comisiones sin transacciones"));
        }
        let mut leaves = Vec::with_capacity(1 + share.txs.len());
        leaves.push(cb.id());
        leaves.extend(share.txs.iter().map(|t| t.full_id()));
        if h.merkle_root != merkle_root(&leaves) {
            return Err(ShareError::BadMerkleRoot);
        }
        {
            let mut seen = std::collections::HashSet::new();
            if leaves[1..].iter().any(|l| !seen.insert(*l)) {
                return Err(ShareError::BadTxs("transacción repetida"));
            }
        }
        if share.tx_bytes() > MAX_SHARE_TX_BYTES {
            return Err(ShareError::BadTxs("transacciones demasiado grandes"));
        }

        // 3. enlaces
        let is_base = base && self.entries.is_empty() && meta.prev_share != NO_PREV;
        let prev_entry = if meta.prev_share == NO_PREV || is_base {
            None
        } else {
            Some(self.entries.get(&meta.prev_share).ok_or(ShareError::UnknownPrevShare)?)
        };
        let (info, window) = chain.header_context(&h.prev_hash).ok_or(ShareError::UnknownParent)?;

        // 4. cabecera
        validate_header_cheap(h, &info, &window, now)?;

        // 5. la altura de bloque no retrocede
        if let Some(p) = prev_entry {
            if h.height < p.share.header.height {
                return Err(ShareError::ParentRegresses);
            }
        }

        // 6. reparto y montos
        let weight = share_weight(&h.target, self.params.ratio);
        // la ventana está completa si llega al primer share o tiene al menos `window - 1` shares
        let window_known = match prev_entry {
            Some(p) => p.rooted || p.depth >= self.params.window.saturating_sub(1) as u64,
            None => !is_base,
        };
        if window_known {
            let prev_id = prev_entry.map(|_| meta.prev_share);
            let expected = self.next_payout(prev_id, meta.miner, weight);
            if cb.outputs.len() != expected.len() {
                return Err(ShareError::BadPayout("número de salidas"));
            }
            if cb.outputs.iter().zip(&expected).any(|(o, (a, p))| o.address != *a || o.share_ppm != *p) {
                return Err(ShareError::BadPayout("el reparto no es el de la ventana"));
            }
            let amounts = chain.expected_amounts(&h.prev_hash, h.height, &expected, &h.target, cb.fees);
            if cb.outputs.iter().zip(&amounts).any(|(o, a)| o.amount != *a) {
                return Err(ShareError::BadPayout("monto distinto del que exige el consenso"));
            }
        }

        // 7. PoW (lo caro, al final)
        let seed = chain.epoch_seed_for(&h.prev_hash, h.height).map_err(ShareError::Chain)?;
        let digest = pow.check_at(h, &seed, &share_target(&h.target, self.params.ratio))?;
        let is_block = meets_target(&digest, &h.target);

        let (height, cum, rooted, depth) = match prev_entry {
            Some(p) => (p.height + 1, p.cum + weight as u128, p.rooted, p.depth + 1),
            None => (1, weight as u128, !is_base, 1),
        };
        self.entries.insert(id, Entry { share, miner: meta.miner, prev: meta.prev_share, weight, height, cum, rooted, depth });
        let new_tip = match self.tip.and_then(|t| self.entries.get(&t)) {
            Some(t) => cum > t.cum,
            None => true,
        };
        if new_tip {
            self.tip = Some(id);
        }
        self.prune();
        Ok(AddShare::Added { new_tip, is_block })
    }

    /// Plantilla de share (nonce 0) sobre el bloque `parent` y la mejor punta actual, para `miner`,
    /// sin transacciones. Ver `template_with`.
    pub fn template(&self, chain: &Chain, parent: Hash32, miner: Address, timestamp: u64) -> Result<Share, ShareError> {
        self.template_with(chain, parent, miner, timestamp, vec![], 0)
    }

    /// Plantilla de share con las transacciones `txs` y sus comisiones `fees` (que el llamador ya
    /// comprobó contra el estado de `parent`; no se admiten más de `MAX_SHARE_TXS` ni más de
    /// `MAX_SHARE_TX_BYTES`). Lleva el reparto de la ventana y los montos que exige el consenso
    /// (comisiones incluidas); el minero solo busca el nonce con `mine_at` contra
    /// `share_target(header.target, ratio)`.
    pub fn template_with(
        &self,
        chain: &Chain,
        parent: Hash32,
        miner: Address,
        timestamp: u64,
        txs: Vec<Transaction>,
        fees: u64,
    ) -> Result<Share, ShareError> {
        if txs.len() > MAX_SHARE_TXS || txs.iter().map(|t| t.to_bytes().len()).sum::<usize>() > MAX_SHARE_TX_BYTES {
            return Err(ShareError::BadTxs("demasiadas transacciones para un share"));
        }
        let (info, window) = chain.header_context(&parent).ok_or(ShareError::UnknownParent)?;
        let target = next_target(&window);
        let weight = share_weight(&target, self.params.ratio);
        let prev = self.tip;
        if let Some(p) = prev.and_then(|t| self.entries.get(&t)) {
            if info.height + 1 < p.share.header.height {
                return Err(ShareError::ParentRegresses);
            }
        }
        let shares = self.next_payout(prev, miner, weight);
        let extra = make_extra(&prev.unwrap_or(NO_PREV), &miner);
        let leaves = txs.iter().map(|t| t.full_id()).collect();
        let Block { header, coinbase, .. } = chain
            .build_template_full(&parent, &shares, timestamp, extra, fees, leaves)
            .map_err(ShareError::Chain)?;
        Ok(Share { header, coinbase, txs })
    }

    /// Descarta shares muy por detrás de la punta (más de 2 ventanas) para acotar la memoria.
    fn prune(&mut self) {
        let keep = (self.params.window as u64).saturating_mul(2).max(16);
        if self.entries.len() as u64 <= keep.saturating_mul(2) {
            return;
        }
        let Some(t) = self.tip.and_then(|t| self.entries.get(&t)) else { return };
        let floor = t.height.saturating_sub(keep);
        self.entries.retain(|_, e| e.height > floor);
    }
}

