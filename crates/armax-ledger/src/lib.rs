//! `armax-ledger`: une la cadena (`armax-chain`) con el estado (`armax-keys::utxo`).
//!
//! * `armax-chain` valida cabeceras, PoW, reparto del coinbase y elige la cadena con más trabajo,
//!   pero no conoce las transacciones: solo ve sus ids (`tx_leaves`) y las comisiones declaradas.
//! * Este crate guarda el cuerpo de cada bloque y mantiene el conjunto de UTXO **de la punta de
//!   la cadena principal**. Cuando la punta cambia (extensión o reorganización) deshace los
//!   bloques que salen y ejecuta los que entran.
//!
//! Los bloques de ramas laterales se guardan sin ejecutarse (como Bitcoin): se ejecutan solo si
//! la rama llega a ser la de más trabajo. Si un bloque con PoW válido falla al ejecutarse
//! (doble gasto, firma falsa, comisiones mal declaradas…), el libro mayor devuelve el estado al
//! de antes de la reorganización, marca ese bloque y sus descendientes como inválidos en la
//! cadena y elige la mejor punta restante.
//!
//! Orden de costes al recibir un bloque: comprobaciones baratas de cuerpo → cabecera y PoW (una
//! ejecución de la VM) → solo entonces las firmas (≈1.2 ms cada una en un teléfono), repartidas
//! entre `verify_threads` hilos. Así un bloque falso sin PoW no gasta CPU en firmas.

use std::collections::HashMap;

use armax_chain::block::MAX_BLOCK_TXS;
use armax_chain::{AddOutcome, Address, Block, Chain, ChainError, Coinbase, DamperParams, PowCheck};
use armax_pow::{BlockHeader, HEADER_LEN};
use armax_keys::tx::{verify_batch, Transaction};
use armax_keys::utxo::{Undo, UtxoError, UtxoSet};

type Hash32 = [u8; 32];

/// Entradas (firmas) máximas por bloque: acota el tiempo de verificación. Con ~1.2 ms por firma
/// en un teléfono, 2,000 entradas son ≈ 2.5 s en un hilo. Parámetro de consenso.
pub const MAX_BLOCK_INPUTS: usize = 2_000;

/// Un bloque con sus transacciones.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FullBlock {
    pub block: Block,
    pub txs: Vec<Transaction>,
}

impl FullBlock {
    pub fn id(&self) -> Hash32 {
        self.block.id()
    }

    /// Formato canónico (también para disco y red):
    /// `cabecera 124 | coinbase_len u32 | coinbase | n_txs u32 | n_txs × (len u32 | tx)`.
    /// Las hojas (`tx_leaves`) no se guardan: se derivan de las transacciones.
    pub fn to_bytes(&self) -> Vec<u8> {
        let cb = self.block.coinbase.to_bytes();
        let mut b = Vec::with_capacity(HEADER_LEN + 8 + cb.len() + self.txs.len() * 300);
        b.extend_from_slice(&self.block.header.to_bytes());
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

    /// Lectura estricta: sin bytes sobrantes, con los límites de tamaño y de cantidad.
    pub fn from_bytes(data: &[u8]) -> Result<FullBlock, &'static str> {
        let mut pos = 0usize;
        let mut take = |n: usize| -> Result<&[u8], &'static str> {
            let end = pos.checked_add(n).ok_or("desbordamiento")?;
            let s = data.get(pos..end).ok_or("datos cortos")?;
            pos = end;
            Ok(s)
        };
        let header = BlockHeader::from_bytes(take(HEADER_LEN)?).map_err(|_| "cabecera inválida")?;
        let cb_len = u32::from_le_bytes(take(4)?.try_into().unwrap()) as usize;
        let coinbase = Coinbase::from_bytes(take(cb_len)?)?;
        let n = u32::from_le_bytes(take(4)?.try_into().unwrap()) as usize;
        if n > MAX_BLOCK_TXS {
            return Err("demasiadas transacciones");
        }
        let mut txs = Vec::with_capacity(n);
        for _ in 0..n {
            let l = u32::from_le_bytes(take(4)?.try_into().unwrap()) as usize;
            txs.push(Transaction::from_bytes(take(l)?).map_err(|_| "transacción inválida")?);
        }
        if pos != data.len() {
            return Err("bytes sobrantes");
        }
        let tx_leaves = txs.iter().map(|t| t.full_id()).collect();
        Ok(FullBlock { block: Block { header, coinbase, tx_leaves }, txs })
    }
}

/// Por qué falló la ejecución de un bloque.
#[derive(Debug, PartialEq, Eq)]
pub enum InvalidReason {
    /// La transacción `index` es inválida o gasta algo que no existe / no es suyo / ya se gastó.
    Tx { index: usize, error: UtxoError },
    /// Las comisiones que declara el coinbase no son entradas − salidas.
    FeesMismatch { declared: u64, computed: u64 },
    /// No se pudieron registrar las salidas del coinbase.
    Coinbase(UtxoError),
}

/// Profundidad por defecto hasta la que se puede deshacer la cadena principal (≈ una semana de
/// bloques de 300 s). Más atrás se descarta el deshacer y una rama que exija revertirlo se rechaza.
pub const DEFAULT_UNDO_DEPTH: u64 = 2016;

#[derive(Debug, PartialEq, Eq)]
pub enum LedgerError {
    Chain(ChainError),
    /// El número de transacciones o sus ids no coinciden con `tx_leaves` del bloque.
    TxLeavesMismatch,
    /// Más de `MAX_BLOCK_INPUTS` entradas en el bloque.
    TooManyInputs(usize),
    /// Un bloque (este u otro de su rama) falló al ejecutarse y quedó invalidado.
    Invalid { block: Hash32, reason: InvalidReason },
    /// La rama con más trabajo exige deshacer más bloques de los que se conservan (`undo_depth`);
    /// se rechaza y se queda en la cadena actual.
    ReorgTooDeep { depth: u64, max: u64 },
    /// Inconsistencia interna (no debería ocurrir).
    Internal(&'static str),
}

impl From<ChainError> for LedgerError {
    fn from(e: ChainError) -> Self {
        LedgerError::Chain(e)
    }
}

impl core::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for LedgerError {}

pub struct Ledger {
    chain: Chain,
    utxos: UtxoSet,
    /// Bloque hasta el cual está aplicado `utxos`. Tras cada operación pública coincide con la punta.
    state_tip: Hash32,
    chain_id: Hash32,
    verify_threads: usize,
    /// Transacciones de todos los bloques conocidos y no invalidados.
    bodies: HashMap<Hash32, Vec<Transaction>>,
    /// Deshacer de cada bloque aplicado (en orden de ejecución; se revierte al revés).
    undos: HashMap<Hash32, Vec<Undo>>,
    /// Cuántos bloques de la cadena principal conservan su deshacer.
    undo_depth: u64,
    /// Los bloques de la cadena principal de altura < `pruned_below` ya no tienen deshacer.
    pruned_below: u64,
    /// Transacciones de los bloques que salieron de la cadena principal en reorganizaciones, aún
    /// no recogidas (el mempool las reincorpora con `take_detached_txs`).
    detached_txs: Vec<Transaction>,
}

fn revert_all(utxos: &mut UtxoSet, undos: Vec<Undo>) {
    for u in undos.into_iter().rev() {
        utxos.revert(u);
    }
}

impl Ledger {
    pub fn new(damper: DamperParams, genesis: Block, verify_threads: usize) -> Result<Ledger, LedgerError> {
        Self::with_maturity(damper, genesis, verify_threads, armax_keys::utxo::COINBASE_MATURITY)
    }

    /// Como `new`, con otra madurez de coinbase (**solo redes de prueba**).
    pub fn with_maturity(
        damper: DamperParams,
        genesis: Block,
        verify_threads: usize,
        maturity: u64,
    ) -> Result<Ledger, LedgerError> {
        let chain = Chain::new(damper, genesis)?;
        let genesis_id = chain.genesis_id();
        Ok(Ledger {
            chain,
            utxos: UtxoSet::with_maturity(maturity),
            state_tip: genesis_id,
            chain_id: genesis_id,
            verify_threads: verify_threads.max(1),
            bodies: HashMap::new(),
            undos: HashMap::new(),
            undo_depth: DEFAULT_UNDO_DEPTH,
            pruned_below: 0,
            detached_txs: Vec::new(),
        })
    }

    pub fn chain(&self) -> &Chain {
        &self.chain
    }
    pub fn utxos(&self) -> &UtxoSet {
        &self.utxos
    }
    /// Identificador de la cadena para las firmas: el id del génesis.
    pub fn chain_id(&self) -> Hash32 {
        self.chain_id
    }
    pub fn tip_id(&self) -> Hash32 {
        self.chain.tip_id()
    }
    pub fn tip_height(&self) -> u64 {
        self.chain.tip_height()
    }
    pub fn balance_of(&self, addr: &Address) -> u128 {
        self.utxos.balance_of(addr)
    }
    /// Entrega (y vacía) las transacciones de los bloques que han salido de la cadena principal
    /// desde la última llamada.
    pub fn take_detached_txs(&mut self) -> Vec<Transaction> {
        std::mem::take(&mut self.detached_txs)
    }
    /// Bloque completo (cabecera, coinbase y transacciones) si lo tenemos. El génesis no tiene
    /// cuerpo guardado: todos lo conocen por construcción.
    pub fn full_block(&self, id: &Hash32) -> Option<FullBlock> {
        let txs = self.bodies.get(id)?.clone();
        let header = self.chain.header(id)?.clone();
        let coinbase = self.chain.coinbase_of(id)?.clone();
        let tx_leaves = txs.iter().map(|t| t.full_id()).collect();
        Some(FullBlock { block: Block { header, coinbase, tx_leaves }, txs })
    }

    pub fn set_verify_threads(&mut self, n: usize) {
        self.verify_threads = n.max(1);
    }

    /// Auditoría: el total de UTXO debe ser lo pagado por los coinbase menos las comisiones
    /// (las comisiones salen de las entradas y vuelven a entrar vía coinbase). Devuelve
    /// `(utxo_total, esperado)`.
    pub fn supply(&self) -> (u128, i128) {
        let paid = self.chain.issued_on_main_chain() as i128;
        let fees = self.chain.fees_on_main_chain() as i128;
        (self.utxos.total_amount(), paid - fees)
    }

    /// Valida un bloque con sus transacciones y lo incorpora; ajusta el estado si la punta cambia.
    pub fn add_block(
        &mut self,
        fb: FullBlock,
        now: u64,
        pow: &mut dyn PowCheck,
    ) -> Result<AddOutcome, LedgerError> {
        let FullBlock { block, txs } = fb;
        let id = block.id();
        if self.chain.contains(&id) {
            return Ok(AddOutcome::AlreadyKnown);
        }
        // 1. comprobaciones baratas del cuerpo
        if txs.len() != block.tx_leaves.len() || txs.iter().zip(&block.tx_leaves).any(|(t, l)| t.full_id() != *l) {
            return Err(LedgerError::TxLeavesMismatch);
        }
        let inputs: usize = txs.iter().map(|t| t.inputs.len()).sum();
        if inputs > MAX_BLOCK_INPUTS {
            return Err(LedgerError::TooManyInputs(inputs));
        }
        // 2. cabecera, reparto del coinbase y PoW
        let outcome = self.chain.add_block(block, now, pow)?;
        self.bodies.insert(id, txs);
        // 3. estado: solo si la punta se movió
        self.sync()?;
        Ok(outcome)
    }

    /// Lleva el estado hasta la punta actual de la cadena. Si un bloque nuevo de la ruta falla,
    /// restaura el estado, lo invalida y reintenta con la mejor punta restante; al final devuelve
    /// el primer error ocurrido.
    fn sync(&mut self) -> Result<(), LedgerError> {
        let mut first_error: Option<LedgerError> = None;
        loop {
            let target = self.chain.tip_id();
            if target == self.state_tip {
                return match first_error {
                    Some(e) => Err(e),
                    None => Ok(()),
                };
            }
            let (detached, attached) = self.chain.path_between(&self.state_tip, &target);

            // ¿se conserva el deshacer de todos los que salen? Si no, la rama es demasiado profunda
            if detached.iter().any(|id| !self.undos.contains_key(id)) {
                if let Some(first) = attached.first() {
                    self.chain.invalidate(first)?;
                    self.bodies.retain(|k, _| !self.chain.is_invalid(k));
                    if first_error.is_none() {
                        first_error = Some(LedgerError::ReorgTooDeep { depth: detached.len() as u64, max: self.undo_depth });
                    }
                    continue;
                }
                return Err(LedgerError::Internal("falta el deshacer de un bloque"));
            }

            // deshacer los bloques que salen (de la punta hacia el ancestro común)
            let mut stash: Vec<(Hash32, Vec<Undo>)> = Vec::with_capacity(detached.len());
            for id in &detached {
                let undo = self.undos.remove(id).ok_or(LedgerError::Internal("falta el deshacer de un bloque"))?;
                // se apila entero: se revierte ahora y se guarda por si hay que rehacerlo
                let copy: Vec<Undo> = undo;
                stash.push((*id, copy));
            }
            // revertir (los Undo se consumen; para poder restaurar se re-ejecutan los bloques)
            for (_, undo) in stash.drain(..) {
                revert_all(&mut self.utxos, undo);
            }

            // ejecutar los bloques que entran, del ancestro común a la nueva punta
            let mut applied: Vec<(Hash32, Vec<Undo>)> = Vec::with_capacity(attached.len());
            let mut failure: Option<(Hash32, InvalidReason)> = None;
            for id in &attached {
                match self.connect(id) {
                    Ok(undos) => applied.push((*id, undos)),
                    Err(reason) => {
                        failure = Some((*id, reason));
                        break;
                    }
                }
            }

            match failure {
                None => {
                    for (id, undos) in applied {
                        self.undos.insert(id, undos);
                    }
                    // del más antiguo al más nuevo, para que los gastos encadenados se reinserten en orden
                    for id in detached.iter().rev() {
                        if let Some(txs) = self.bodies.get(id) {
                            self.detached_txs.extend(txs.iter().cloned());
                        }
                    }
                    self.state_tip = target;
                    self.prune_undos();
                    // continúa el bucle por si la punta cambió (no debería) y para devolver el error previo
                }
                Some((bad, reason)) => {
                    // restaurar: quitar lo aplicado y volver a ejecutar los bloques que habían salido
                    for (_, undos) in applied.into_iter().rev() {
                        revert_all(&mut self.utxos, undos);
                    }
                    for id in detached.iter().rev() {
                        match self.connect(id) {
                            Ok(undos) => {
                                self.undos.insert(*id, undos);
                            }
                            Err(_) => return Err(LedgerError::Internal("un bloque válido dejó de serlo al rehacerlo")),
                        }
                    }
                    self.chain.invalidate(&bad)?;
                    self.bodies.retain(|k, _| !self.chain.is_invalid(k));
                    if first_error.is_none() {
                        first_error = Some(LedgerError::Invalid { block: bad, reason });
                    }
                    // el estado vuelve a `state_tip`; el bucle compara con la nueva punta
                }
            }
        }
    }

    /// Descarta el deshacer de los bloques de la cadena principal más antiguos que `undo_depth`.
    fn prune_undos(&mut self) {
        let below = self.chain.tip_height().saturating_sub(self.undo_depth);
        for h in self.pruned_below..below {
            if let Some(id) = self.chain.id_at_height(h) {
                self.undos.remove(&id);
            }
        }
        if below > self.pruned_below {
            self.pruned_below = below;
        }
    }

    /// Cambia cuántos bloques se pueden deshacer (mínimo 1). Poda de inmediato lo que sobre.
    pub fn set_undo_depth(&mut self, depth: u64) {
        self.undo_depth = depth.max(1);
        self.prune_undos();
    }

    /// Bloques con deshacer guardado (para vigilar la memoria).
    pub fn undo_count(&self) -> usize {
        self.undos.len()
    }

    /// Ejecuta un bloque sobre el estado actual (que debe ser el de su padre).
    fn connect(&mut self, id: &Hash32) -> Result<Vec<Undo>, InvalidReason> {
        let height = self.chain.header(id).expect("bloque conocido").height;
        let txs = self.bodies.get(id).expect("cuerpo guardado");
        let verified = verify_batch(txs, &self.chain_id, self.verify_threads)
            .map_err(|(index, e)| InvalidReason::Tx { index, error: UtxoError::Tx(e) })?;

        let mut undos: Vec<Undo> = Vec::with_capacity(verified.len() + 1);
        let mut fees: u128 = 0;
        for (index, v) in verified.into_iter().enumerate() {
            match self.utxos.apply_verified(v, height) {
                Ok((fee, undo)) => {
                    fees += fee as u128;
                    undos.push(undo);
                }
                Err(error) => {
                    revert_all(&mut self.utxos, undos);
                    return Err(InvalidReason::Tx { index, error });
                }
            }
        }
        let cb = self.chain.coinbase_of(id).expect("bloque conocido");
        if fees != cb.fees as u128 {
            let declared = cb.fees;
            revert_all(&mut self.utxos, undos);
            return Err(InvalidReason::FeesMismatch { declared, computed: fees.min(u64::MAX as u128) as u64 });
        }
        let outs: Vec<(Address, u64)> = cb.outputs.iter().map(|o| (o.address, o.amount)).collect();
        match self.utxos.apply_coinbase(cb.id(), height, &outs) {
            Ok(undo) => undos.push(undo),
            Err(e) => {
                revert_all(&mut self.utxos, undos);
                return Err(InvalidReason::Coinbase(e));
            }
        }
        Ok(undos)
    }

    /// Elige de `candidates` (en orden) las transacciones que se pueden aplicar juntas sobre la
    /// punta actual, respetando `MAX_BLOCK_TXS` y `MAX_BLOCK_INPUTS`; devuelve también sus
    /// comisiones. El estado queda intacto.
    pub fn select_txs(&mut self, candidates: &[Transaction]) -> (Vec<Transaction>, u64) {
        self.select_txs_within(candidates, MAX_BLOCK_TXS, usize::MAX)
    }

    /// Como `select_txs` con topes propios: a lo sumo `max_txs` transacciones que sumen a lo sumo
    /// `max_bytes` serializadas (lo usa el pool, cuyos shares son más pequeños que un bloque).
    pub fn select_txs_within(&mut self, candidates: &[Transaction], max_txs: usize, max_bytes: usize) -> (Vec<Transaction>, u64) {
        let height = self.chain.tip_height() + 1;
        let mut chosen: Vec<Transaction> = vec![];
        let mut undos: Vec<Undo> = vec![];
        let (mut fees, mut inputs, mut bytes) = (0u64, 0usize, 0usize);
        for tx in candidates {
            let size = tx.to_bytes().len();
            if chosen.len() >= max_txs.min(MAX_BLOCK_TXS)
                || inputs + tx.inputs.len() > MAX_BLOCK_INPUTS
                || bytes.saturating_add(size) > max_bytes
            {
                continue;
            }
            if let Ok((fee, undo)) = self.utxos.apply_tx(tx, height, &self.chain_id) {
                fees += fee;
                inputs += tx.inputs.len();
                bytes += size;
                undos.push(undo);
                chosen.push(tx.clone());
            }
        }
        revert_all(&mut self.utxos, undos);
        (chosen, fees)
    }

    /// Plantilla para minar sobre la punta actual: elige de `candidates` (en orden) las
    /// transacciones que se pueden aplicar juntas, respetando `MAX_BLOCK_TXS` y `MAX_BLOCK_INPUTS`,
    /// y fija las comisiones en el coinbase. El nonce queda en 0.
    pub fn build_template(
        &mut self,
        shares: &[(Address, u32)],
        timestamp: u64,
        extra: Vec<u8>,
        candidates: &[Transaction],
    ) -> Result<FullBlock, LedgerError> {
        let parent = self.chain.tip_id();
        let (chosen, fees) = self.select_txs(candidates);
        let leaves: Vec<Hash32> = chosen.iter().map(|t| t.full_id()).collect();
        let block = self.chain.build_template_full(&parent, shares, timestamp, extra, fees, leaves)?;
        Ok(FullBlock { block, txs: chosen })
    }
}
