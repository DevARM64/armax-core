//! `armax-mempool`: transacciones pendientes de entrar en un bloque.
//!
//! # Reglas de admisión (de la más barata a la más cara)
//! 1. Tamaño ≤ `MAX_TX_BYTES`, 1..=64 entradas y salidas, sin entradas repetidas.
//! 2. Cada entrada existe en el UTXO **confirmado** de la punta, la clave firma para su dirección
//!    y, si es un coinbase, ya maduró en el próximo bloque. Se calcula la comisión.
//! 3. Comisión ≥ `min_fee_per_kb` del tamaño.
//! 4. Conflictos y reemplazo (ver abajo) y hueco en el pool (ver abajo).
//! 5. Solo al final, las firmas (≈1.2 ms cada una): basura sin fondos no cuesta CPU de firmas.
//!
//! # Sin gastos encadenados
//! Una transacción solo puede gastar salidas ya confirmadas, no las de otra del mempool. Es más
//! simple y evita cadenas de dependencias que complican el reemplazo y la expulsión; quien
//! quiera reutilizar su cambio espera un bloque. (Se podrá relajar más adelante.)
//!
//! # Reemplazo por comisión
//! Si la transacción gasta algo que ya gasta otra del pool, la reemplaza solo si paga **más en
//! total** que todas las que desplaza más `min_fee_per_kb` por su propio tamaño, y su tasa
//! (comisión/byte) es mayor que la de cada una de ellas. Así reemplazar no sale gratis a quien
//! inunda la red con versiones.
//!
//! # Límites de memoria
//! `max_bytes` y `max_txs`. Si no cabe, se expulsan las de menor tasa, pero solo si todas las
//! expulsadas pagan menos tasa que la nueva; si no, la nueva se rechaza (`PoolFull`) y no se
//! toca nada.
//!
//! # Reorganizaciones y bloques nuevos
//! `on_chain_update` revalida el pool contra el estado nuevo (descarta lo ya gastado por bloques),
//! y reincorpora las transacciones de los bloques que salieron de la cadena principal.
//!
//! Las comparaciones de tasa usan multiplicación cruzada en `u128` (sin decimales ni redondeo) y
//! los empates se rompen por `txid`, de modo que el orden es determinista.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use armax_keys::address::address_from_public_key;
use armax_keys::tx::{Hash32, OutPoint, Transaction, TxError, MAX_TX_INPUTS, MAX_TX_OUTPUTS};
use armax_ledger::Ledger;

/// Tamaño máximo de una transacción serializada (64 entradas × 132 + 64 salidas × 40 ≈ 11 KiB).
pub const MAX_TX_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MempoolConfig {
    pub max_bytes: usize,
    pub max_txs: usize,
    /// Comisión mínima por 1,000 bytes, en unidades (1 ARM = 100,000,000 unidades).
    pub min_fee_per_kb: u64,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        // 4 MiB y 5,000 transacciones: razonable para un teléfono. 1,000 unidades/kB = 1 unidad/byte.
        MempoolConfig { max_bytes: 4 * 1024 * 1024, max_txs: 5_000, min_fee_per_kb: 1_000 }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum MempoolError {
    TooLarge(usize),
    BadShape,
    DuplicateInput,
    MissingInput(usize),
    WrongOwner(usize),
    Immature(usize),
    OutputsExceedInputs,
    FeeTooLow { fee: u64, needed: u64 },
    /// Choca con transacciones del pool y no paga lo suficiente para reemplazarlas.
    ReplacementRejected { needed_fee: u64 },
    /// El pool está lleno y esta transacción no paga más tasa que las que habría que expulsar.
    PoolFull,
    Invalid(TxError),
}

#[derive(Debug, PartialEq, Eq)]
pub enum AddResult {
    Added,
    /// Entró desplazando a estas transacciones (reemplazo y/o expulsión por falta de espacio).
    AddedDisplacing(Vec<Hash32>),
    AlreadyKnown,
}

#[derive(Clone, Debug)]
struct Entry {
    tx: Transaction,
    fee: u64,
    size: usize,
}

/// `a` paga más tasa que `b` (fee/size), sin decimales.
fn rate_cmp(a: (u64, usize), b: (u64, usize)) -> Ordering {
    (a.0 as u128 * b.1 as u128).cmp(&(b.0 as u128 * a.1 as u128))
}

pub struct Mempool {
    cfg: MempoolConfig,
    entries: HashMap<Hash32, Entry>,
    /// Salida gastada → transacción del pool que la gasta.
    spent: HashMap<OutPoint, Hash32>,
    bytes: usize,
}

impl Mempool {
    pub fn new(cfg: MempoolConfig) -> Mempool {
        Mempool { cfg, entries: HashMap::new(), spent: HashMap::new(), bytes: 0 }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn total_bytes(&self) -> usize {
        self.bytes
    }
    /// Alguna transacción del pool ya gasta esta salida.
    pub fn is_spent(&self, op: &OutPoint) -> bool {
        self.spent.contains_key(op)
    }
    pub fn contains(&self, txid: &Hash32) -> bool {
        self.entries.contains_key(txid)
    }
    pub fn fee_of(&self, txid: &Hash32) -> Option<u64> {
        self.entries.get(txid).map(|e| e.fee)
    }
    pub fn get(&self, txid: &Hash32) -> Option<&Transaction> {
        self.entries.get(txid).map(|e| &e.tx)
    }

    /// Comisión y comprobaciones con estado, sin firmas. `height` = altura del próximo bloque.
    fn check_state(tx: &Transaction, ledger: &Ledger) -> Result<u64, MempoolError> {
        let height = ledger.tip_height() + 1;
        let mut total_in = 0u128;
        for (i, inp) in tx.inputs.iter().enumerate() {
            let u = ledger.utxos().get(&inp.prev).ok_or(MempoolError::MissingInput(i))?;
            if address_from_public_key(&inp.public_key) != u.address {
                return Err(MempoolError::WrongOwner(i));
            }
            if u.coinbase && height < u.height.saturating_add(ledger.utxos().maturity()) {
                return Err(MempoolError::Immature(i));
            }
            total_in += u.amount as u128;
        }
        let out = tx.output_total();
        if out > total_in {
            return Err(MempoolError::OutputsExceedInputs);
        }
        Ok((total_in - out).min(u64::MAX as u128) as u64)
    }

    fn min_fee_for(&self, size: usize) -> u64 {
        ((self.cfg.min_fee_per_kb as u128 * size as u128 + 999) / 1000).min(u64::MAX as u128) as u64
    }

    /// Admite una transacción respecto al estado actual del libro mayor.
    pub fn add(&mut self, tx: Transaction, ledger: &Ledger) -> Result<AddResult, MempoolError> {
        // 1. forma
        if !(1..=MAX_TX_INPUTS).contains(&tx.inputs.len()) || !(1..=MAX_TX_OUTPUTS).contains(&tx.outputs.len()) {
            return Err(MempoolError::BadShape);
        }
        let bytes = tx.to_bytes();
        let size = bytes.len();
        if size > MAX_TX_BYTES {
            return Err(MempoolError::TooLarge(size));
        }
        let txid = tx.txid();
        if self.entries.contains_key(&txid) {
            return Ok(AddResult::AlreadyKnown);
        }
        let mut seen = HashSet::with_capacity(tx.inputs.len());
        if !tx.inputs.iter().all(|i| seen.insert(i.prev)) {
            return Err(MempoolError::DuplicateInput);
        }
        // 2. estado
        let fee = Self::check_state(&tx, ledger)?;
        // 3. comisión mínima
        let needed = self.min_fee_for(size);
        if fee < needed {
            return Err(MempoolError::FeeTooLow { fee, needed });
        }
        // 4a. conflictos / reemplazo
        let mut conflicts: Vec<Hash32> = tx.inputs.iter().filter_map(|i| self.spent.get(&i.prev).copied()).collect();
        conflicts.sort();
        conflicts.dedup();
        if !conflicts.is_empty() {
            let displaced_fee: u128 = conflicts.iter().map(|c| self.entries[c].fee as u128).sum();
            let needed_fee = displaced_fee + needed as u128;
            let beats_rates = conflicts.iter().all(|c| {
                let e = &self.entries[c];
                rate_cmp((fee, size), (e.fee, e.size)) == Ordering::Greater
            });
            if (fee as u128) < needed_fee || !beats_rates {
                return Err(MempoolError::ReplacementRejected { needed_fee: needed_fee.min(u64::MAX as u128) as u64 });
            }
        }
        // 4b. espacio: qué habría que expulsar (sin tocar nada todavía)
        let freed_bytes: usize = conflicts.iter().map(|c| self.entries[c].size).sum();
        let mut count_after = self.entries.len() - conflicts.len() + 1;
        let mut bytes_after = self.bytes - freed_bytes + size;
        let mut evict: Vec<Hash32> = vec![];
        if count_after > self.cfg.max_txs || bytes_after > self.cfg.max_bytes {
            let mut by_rate: Vec<(&Hash32, &Entry)> =
                self.entries.iter().filter(|(id, _)| !conflicts.contains(id)).collect();
            by_rate.sort_by(|a, b| rate_cmp((a.1.fee, a.1.size), (b.1.fee, b.1.size)).then(a.0.cmp(b.0)));
            for (id, e) in by_rate {
                if count_after <= self.cfg.max_txs && bytes_after <= self.cfg.max_bytes {
                    break;
                }
                if rate_cmp((e.fee, e.size), (fee, size)) != Ordering::Less {
                    return Err(MempoolError::PoolFull);
                }
                evict.push(*id);
                count_after -= 1;
                bytes_after -= e.size;
            }
            if count_after > self.cfg.max_txs || bytes_after > self.cfg.max_bytes {
                return Err(MempoolError::PoolFull); // p. ej. una sola transacción mayor que max_bytes
            }
        }
        // 5. firmas, lo último
        tx.verify(&ledger.chain_id()).map_err(MempoolError::Invalid)?;

        // todo aceptado: mutar
        let mut displaced = conflicts;
        displaced.extend(evict);
        for id in &displaced {
            self.remove(id);
        }
        for i in &tx.inputs {
            self.spent.insert(i.prev, txid);
        }
        self.bytes += size;
        self.entries.insert(txid, Entry { tx, fee, size });
        Ok(if displaced.is_empty() { AddResult::Added } else { AddResult::AddedDisplacing(displaced) })
    }

    fn remove(&mut self, txid: &Hash32) -> Option<Entry> {
        let e = self.entries.remove(txid)?;
        for i in &e.tx.inputs {
            self.spent.remove(&i.prev);
        }
        self.bytes -= e.size;
        Some(e)
    }

    /// Transacciones en orden de selección: mayor tasa primero, empates por `txid`.
    pub fn candidates(&self) -> Vec<Transaction> {
        let mut v: Vec<(&Hash32, &Entry)> = self.entries.iter().collect();
        v.sort_by(|a, b| rate_cmp((b.1.fee, b.1.size), (a.1.fee, a.1.size)).then(a.0.cmp(b.0)));
        v.into_iter().map(|(_, e)| e.tx.clone()).collect()
    }

    /// Descarta lo que dejó de ser válido contra el estado actual (gastado o inexistente tras un
    /// bloque nuevo o un reorg). No repite las firmas, que ya se comprobaron. Devuelve cuántas.
    pub fn revalidate(&mut self, ledger: &Ledger) -> usize {
        let bad: Vec<Hash32> = self
            .entries
            .iter()
            .filter(|(_, e)| Self::check_state(&e.tx, ledger).is_err())
            .map(|(id, _)| *id)
            .collect();
        for id in &bad {
            self.remove(id);
        }
        bad.len()
    }

    /// A llamar tras cada bloque aceptado: revalida el pool y reincorpora las transacciones de
    /// los bloques que salieron de la cadena principal (las que sigan siendo válidas).
    pub fn on_chain_update(&mut self, ledger: &mut Ledger) {
        let detached = ledger.take_detached_txs();
        self.revalidate(ledger);
        for tx in detached {
            let _ = self.add(tx, ledger);
        }
    }
}
