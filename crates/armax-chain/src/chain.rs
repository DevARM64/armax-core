//! Índice de bloques, validación completa de bloques y elección de cadena por trabajo acumulado.
//!
//! Regla de elección: gana la cadena con mayor **trabajo acumulado** (Σ `block_work(target)`),
//! no la más larga. En empate se mantiene la punta actual (la primera vista).
//!
//! Orden de validación de un bloque (lo barato primero; el PoW, que cuesta una ejecución
//! completa de la VM, al final):
//!   1. padre conocido
//!   2. cabecera: versión, altura, enlace, target exacto de LWMA, mediana de tiempo, límite de futuro
//!   3. cuerpo: altura del coinbase, tamaño de `extra`, forma de las salidas (1..=64, partes
//!      mínimas, direcciones distintas, suma exacta), raíz de Merkle, montos exactos tras el
//!      amortiguador de cada dirección
//!   4. PoW con la semilla de época
//!
//! Los bloques cuyo padre se desconoce se rechazan con `UnknownParent`; guardarlos como huérfanos
//! es responsabilidad de la capa de red.

use core::fmt;
use std::collections::HashMap;

use armax_pow::consensus::{
    epoch_of, epoch_seed_height, genesis_epoch_seed, initial_target, HEADER_VERSION, LWMA_WINDOW,
};
use armax_pow::lwma::next_target;
use armax_pow::{
    block_work, validate_header_cheap, BlockHeader, Hash32, HeaderError, ParentInfo, WindowEntry, U256,
};

use crate::block::{
    Block, Coinbase, Output, MAX_BLOCK_TXS, MAX_COINBASE_EXTRA, MAX_COINBASE_OUTPUTS, MIN_SHARE_PPM,
    SHARE_TOTAL,
};
use crate::damper::{allowed_blocks, damped_amount, DamperParams};
use crate::emission::subsidy;
use crate::merkle::merkle_root;
use crate::pow_check::PowCheck;
use crate::types::Address;

#[derive(Debug, PartialEq, Eq)]
pub enum ChainError {
    UnknownParent,
    /// El padre fue marcado como inválido (su ejecución falló): no se acepta nada encima.
    InvalidParent,
    /// Más de `MAX_BLOCK_TXS` transacciones.
    TooManyTxs(usize),
    /// `invalidate` con un id desconocido o con el génesis.
    CannotInvalidate,
    Header(HeaderError),
    BadCoinbaseHeight { expected: u64, got: u64 },
    CoinbaseExtraTooLong(usize),
    BadMerkleRoot,
    /// Forma inválida de las salidas del coinbase (cantidad, partes, duplicados, suma).
    BadCoinbaseOutputs(&'static str),
    /// El monto de la salida `index` no es el que resulta del subsidio, su parte y el amortiguador.
    BadPayout { index: usize, expected: u64, got: u64 },
    BadGenesis(&'static str),
    MissingAncestor,
    /// Una cabecera no enlaza con la anterior del lote.
    HeadersNotLinked,
}

impl From<HeaderError> for ChainError {
    fn from(e: HeaderError) -> Self {
        ChainError::Header(e)
    }
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ChainError {}

/// Resultado de validar una cadena de cabeceras sin sus cuerpos (`Chain::validate_headers`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderRun {
    /// Último bloque que ya teníamos y del que cuelga la primera cabecera nueva.
    pub fork_point: Hash32,
    /// Ids de las cabeceras nuevas (que aún no son bloques nuestros), en orden.
    pub new_ids: Vec<Hash32>,
    /// Trabajo acumulado de la última cabecera del lote.
    pub work: U256,
    /// Altura de la última cabecera del lote.
    pub tip_height: u64,
}

/// Validador incremental de una cadena de cabeceras **sin sus cuerpos**.
///
/// Es la mitad barata de `Chain::add_block`: enlace, versión, altura, target exacto de LWMA,
/// mediana de tiempo, límite de futuro y PoW con la semilla de época. No toca la cadena y se puede
/// alimentar de a poco (cada `push` es una cabecera, una ejecución de la VM): quien lo use puede
/// repartir el trabajo entre llamadas para no bloquear. Lo que no comprueba (coinbase, montos,
/// transacciones) se comprueba al llegar los cuerpos; pero con esto un par no puede hacernos
/// descargar cuerpos de una cadena sin el trabajo que dice: el trabajo de las cabeceras es real o
/// la validación falla.
///
/// La primera cabecera nueva debe colgar de un bloque nuestro (`fork_point`). Las cabeceras que ya
/// son bloques nuestros solo se admiten al principio (se saltan). Una rama que pasa por un bloque
/// marcado inválido se rechaza. La cadena puede crecer entre `push` y `push`: los bloques no se
/// borran, así que el punto de bifurcación sigue valiendo.
#[derive(Default)]
pub struct HeaderValidator {
    local: HashMap<Hash32, (BlockHeader, U256)>,
    new_ids: Vec<Hash32>,
    fork_point: Option<Hash32>,
    prev: Option<(Hash32, u64, U256)>, // id, altura, trabajo acumulado
}

impl HeaderValidator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Cabeceras nuevas validadas hasta ahora.
    pub fn len(&self) -> usize {
        self.new_ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.new_ids.is_empty()
    }

    /// Ids de las cabeceras nuevas validadas hasta ahora.
    pub fn new_ids(&self) -> &[Hash32] {
        &self.new_ids
    }

    pub fn push(&mut self, chain: &Chain, h: &BlockHeader, now: u64, pow: &mut dyn PowCheck) -> Result<(), ChainError> {
        let id = h.id();
        if let Some((pid, _, _)) = &self.prev {
            if h.prev_hash != *pid {
                return Err(ChainError::HeadersNotLinked);
            }
        }
        if let Some(e) = chain.blocks.get(&id) {
            // ya es nuestro: solo vale como prefijo del lote
            if !self.new_ids.is_empty() {
                return Err(ChainError::HeadersNotLinked);
            }
            if e.invalid {
                return Err(ChainError::InvalidParent);
            }
            self.prev = Some((id, e.header.height, e.cum_work));
            self.fork_point = Some(id);
            return Ok(());
        }
        let (parent_id, parent_height, parent_work) = match &self.prev {
            Some(p) => (p.0, p.1, p.2),
            None => {
                let p = chain.blocks.get(&h.prev_hash).ok_or(ChainError::UnknownParent)?;
                if p.invalid {
                    return Err(ChainError::InvalidParent);
                }
                self.fork_point = Some(h.prev_hash);
                (h.prev_hash, p.header.height, p.cum_work)
            }
        };
        let window = chain.lwma_window_with(&self.local, &parent_id);
        validate_header_cheap(h, &ParentInfo { height: parent_height, id: parent_id }, &window, now)?;
        let seed = chain.epoch_seed_with(&self.local, &parent_id, h.height)?;
        pow.check(h, &seed)?;
        let work = parent_work.checked_add(block_work(&h.target)).expect("el trabajo acumulado no desborda 256 bits");
        self.local.insert(id, (h.clone(), work));
        self.new_ids.push(id);
        self.prev = Some((id, h.height, work));
        Ok(())
    }

    /// Resultado del lote. Error si no se empujó ninguna cabecera.
    pub fn finish(self) -> Result<HeaderRun, ChainError> {
        match (self.fork_point, self.prev) {
            (Some(fork_point), Some((_, tip_height, work))) => {
                Ok(HeaderRun { fork_point, new_ids: self.new_ids, work, tip_height })
            }
            _ => Err(ChainError::UnknownParent), // lote vacío
        }
    }
}

/// Qué pasó al añadir un bloque válido.
#[derive(Debug, PartialEq, Eq)]
pub enum AddOutcome {
    /// Ya lo teníamos.
    AlreadyKnown,
    /// Guardado en una rama con menos trabajo que la punta actual.
    SideChain,
    /// Nueva punta que extiende directamente la anterior.
    Extended,
    /// Nueva punta en otra rama. `detached`: bloques que dejan la cadena principal (de la punta
    /// antigua hacia el ancestro común); `attached`: bloques que entran (del ancestro común a la
    /// nueva punta).
    Reorg { detached: Vec<Hash32>, attached: Vec<Hash32> },
}

struct Entry {
    header: BlockHeader,
    coinbase: Coinbase,
    cum_work: U256,
    /// Orden de llegada (desempata ramas con el mismo trabajo: gana la primera vista).
    seq: u64,
    /// Marcado por `invalidate`: ni el bloque ni sus descendientes pueden ser la punta.
    invalid: bool,
}

/// Forma de un reparto: entre 1 y `MAX_COINBASE_OUTPUTS` salidas, cada una con al menos
/// `MIN_SHARE_PPM`, direcciones distintas y partes que suman exactamente `SHARE_TOTAL`.
pub fn check_shares(shares: &[(Address, u32)]) -> Result<(), ChainError> {
    if shares.is_empty() {
        return Err(ChainError::BadCoinbaseOutputs("sin salidas"));
    }
    if shares.len() > MAX_COINBASE_OUTPUTS {
        return Err(ChainError::BadCoinbaseOutputs("demasiadas salidas"));
    }
    if shares.iter().any(|(_, s)| *s < MIN_SHARE_PPM) {
        return Err(ChainError::BadCoinbaseOutputs("parte por debajo del mínimo"));
    }
    let mut seen = std::collections::HashSet::with_capacity(shares.len());
    if !shares.iter().all(|(a, _)| seen.insert(*a)) {
        return Err(ChainError::BadCoinbaseOutputs("dirección repetida"));
    }
    // cada parte ≤ SHARE_TOTAL (u32) y hay ≤ 64: la suma cabe en u64
    if shares.iter().map(|(_, s)| *s as u64).sum::<u64>() != SHARE_TOTAL as u64 {
        return Err(ChainError::BadCoinbaseOutputs("las partes no suman 1,000,000"));
    }
    Ok(())
}

pub struct Chain {
    damper: DamperParams,
    blocks: HashMap<Hash32, Entry>,
    tip: Hash32,
    genesis: Hash32,
    next_seq: u64,
    /// Índice por altura de la cadena principal (génesis → punta): `main[h]` es el id a altura `h`.
    main: Vec<Hash32>,
    /// Totales de la cadena principal, mantenidos de forma incremental (recompensas y comisiones).
    main_issued: u64,
    main_fees: u64,
}

impl Chain {
    /// Crea la cadena a partir del génesis. Se comprueba su forma, no su PoW (es una constante).
    pub fn new(damper: DamperParams, genesis: Block) -> Result<Self, ChainError> {
        let g = &genesis;
        if g.header.height != 0 || g.header.prev_hash != [0u8; 32] {
            return Err(ChainError::BadGenesis("altura/prev_hash"));
        }
        if g.header.version != HEADER_VERSION {
            return Err(ChainError::BadGenesis("versión"));
        }
        if g.coinbase.height != 0 || g.coinbase.fees != 0 || !g.coinbase.outputs.is_empty() || !g.tx_leaves.is_empty() {
            return Err(ChainError::BadGenesis("el génesis no puede emitir ni pagar a nadie"));
        }
        if g.coinbase.extra.len() > MAX_COINBASE_EXTRA {
            return Err(ChainError::BadGenesis("extra demasiado largo"));
        }
        if g.header.merkle_root != g.expected_merkle_root() {
            return Err(ChainError::BadGenesis("raíz de Merkle"));
        }
        if g.header.target != initial_target() {
            return Err(ChainError::BadGenesis("target inicial"));
        }
        let id = g.id();
        let work = block_work(&g.header.target);
        let mut blocks = HashMap::new();
        blocks.insert(
            id,
            Entry { header: genesis.header.clone(), coinbase: genesis.coinbase.clone(), cum_work: work, seq: 0, invalid: false },
        );
        Ok(Self { damper, blocks, tip: id, genesis: id, next_seq: 1, main: vec![id], main_issued: 0, main_fees: 0 })
    }

    pub fn genesis_id(&self) -> Hash32 {
        self.genesis
    }
    pub fn tip_id(&self) -> Hash32 {
        self.tip
    }
    pub fn tip_height(&self) -> u64 {
        self.blocks[&self.tip].header.height
    }
    pub fn tip_work(&self) -> U256 {
        self.blocks[&self.tip].cum_work
    }
    pub fn contains(&self, id: &Hash32) -> bool {
        self.blocks.contains_key(id)
    }
    pub fn header(&self, id: &Hash32) -> Option<&BlockHeader> {
        self.blocks.get(id).map(|e| &e.header)
    }
    pub fn cumulative_work(&self, id: &Hash32) -> Option<U256> {
        self.blocks.get(id).map(|e| e.cum_work)
    }
    /// Total emitido por el bloque (suma de sus salidas).
    pub fn reward_of(&self, id: &Hash32) -> Option<u64> {
        self.blocks.get(id).map(|e| e.coinbase.reward())
    }
    /// Salidas del coinbase del bloque (dirección, parte y monto cobrado).
    pub fn payouts_of(&self, id: &Hash32) -> Option<&[Output]> {
        self.blocks.get(id).map(|e| e.coinbase.outputs.as_slice())
    }
    pub fn coinbase_of(&self, id: &Hash32) -> Option<&Coinbase> {
        self.blocks.get(id).map(|e| &e.coinbase)
    }
    pub fn is_invalid(&self, id: &Hash32) -> bool {
        self.blocks.get(id).map_or(false, |e| e.invalid)
    }
    pub fn len(&self) -> usize {
        self.blocks.len()
    }
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Hasta `n` entradas desde `tip` hacia atrás (la más reciente primero), sin pasar del génesis.
    fn walk(&self, tip: &Hash32, n: usize) -> Vec<&Entry> {
        let mut out = Vec::with_capacity(n.min(4096));
        let mut cur = *tip;
        while out.len() < n {
            let Some(e) = self.blocks.get(&cur) else { break };
            out.push(e);
            if e.header.height == 0 {
                break;
            }
            cur = e.header.prev_hash;
        }
        out
    }

    /// Ventana de LWMA que termina en `parent` (más antiguo primero).
    fn lwma_window(&self, parent: &Hash32) -> Vec<WindowEntry> {
        self.lwma_window_with(&HashMap::new(), parent)
    }

    /// Cabecera por id: primero las del lote en validación, luego las de la cadena.
    fn header_of<'a>(&'a self, local: &'a HashMap<Hash32, (BlockHeader, U256)>, id: &Hash32) -> Option<&'a BlockHeader> {
        local.get(id).map(|(h, _)| h).or_else(|| self.blocks.get(id).map(|e| &e.header))
    }

    fn lwma_window_with(&self, local: &HashMap<Hash32, (BlockHeader, U256)>, parent: &Hash32) -> Vec<WindowEntry> {
        let mut v: Vec<WindowEntry> = Vec::with_capacity(LWMA_WINDOW + 1);
        let mut cur = *parent;
        while v.len() < LWMA_WINDOW + 1 {
            let Some(h) = self.header_of(local, &cur) else { break };
            v.push((h.timestamp, h.target));
            if h.height == 0 {
                break;
            }
            cur = h.prev_hash;
        }
        v.reverse();
        v
    }

    /// Contexto para validar un hijo de `parent` sin añadirlo: datos del padre y su ventana de LWMA.
    /// `None` si el padre no se conoce o fue marcado inválido. Lo usa la validación de shares.
    pub fn header_context(&self, parent: &Hash32) -> Option<(ParentInfo, Vec<WindowEntry>)> {
        let p = self.blocks.get(parent)?;
        if p.invalid {
            return None;
        }
        Some((ParentInfo { height: p.header.height, id: *parent }, self.lwma_window(parent)))
    }

    /// Semilla de época para un bloque de altura `height` cuyo padre es `parent`.
    /// Semilla de época que debe usar el PoW de un bloque de altura `height` hijo de `parent`
    /// (el minero la necesita para construir la tabla de operaciones).
    pub fn epoch_seed_for(&self, parent: &Hash32, height: u64) -> Result<[u8; 32], ChainError> {
        self.epoch_seed(parent, height)
    }

    fn epoch_seed(&self, parent: &Hash32, height: u64) -> Result<[u8; 32], ChainError> {
        self.epoch_seed_with(&HashMap::new(), parent, height)
    }

    fn epoch_seed_with(
        &self,
        local: &HashMap<Hash32, (BlockHeader, U256)>,
        parent: &Hash32,
        height: u64,
    ) -> Result<[u8; 32], ChainError> {
        let Some(seed_h) = epoch_seed_height(epoch_of(height)) else {
            return Ok(genesis_epoch_seed());
        };
        let mut cur = *parent;
        loop {
            let h = self.header_of(local, &cur).ok_or(ChainError::MissingAncestor)?;
            if h.height == seed_h {
                return Ok(cur);
            }
            if h.height < seed_h || h.height == 0 {
                return Err(ChainError::MissingAncestor);
            }
            cur = h.prev_hash;
        }
    }

    /// Valida una cadena de cabeceras **sin sus cuerpos** y devuelve su trabajo acumulado.
    /// (Atajo de `HeaderValidator` para un lote completo.)
    pub fn validate_headers(
        &self,
        headers: &[BlockHeader],
        now: u64,
        pow: &mut dyn PowCheck,
    ) -> Result<HeaderRun, ChainError> {
        let mut v = HeaderValidator::new();
        for h in headers {
            v.push(self, h, now, pow)?;
        }
        v.finish()
    }

    /// Montos exactos que debe cobrar cada salida de un bloque de altura `height` con ese `target`,
    /// hijo de `parent`, dado el reparto `shares` (ya validado con `check_shares`) y las comisiones
    /// `fees` del bloque.
    ///
    /// Monto de la salida = subsidio amortiguado + `fees · parte / 1e6`. El subsidio bruto es
    /// `subsidio · parte / 1e6`; cada dirección acumula su parte de los bloques de la ventana (los
    /// `window-1` anteriores más el actual) y el amortiguador recorta ese subsidio en proporción si
    /// supera lo permitido. Las comisiones no se recortan. Quien reparte su parte entre muchos mineros
    /// no recorta a ninguno mientras cada uno quede por debajo del tope. Los restos de redondeo no se
    /// emiten.
    pub fn expected_amounts(
        &self,
        parent: &Hash32,
        height: u64,
        shares: &[(Address, u32)],
        target: &U256,
        fees: u64,
    ) -> Vec<u64> {
        let base = subsidy(height);
        let allowed = allowed_blocks(&block_work(target), &self.damper);
        let mut counts: HashMap<Address, u64> = shares.iter().map(|(a, s)| (*a, *s as u64)).collect();
        for e in self.walk(parent, self.damper.window.saturating_sub(1)) {
            if e.header.height == 0 {
                continue;
            }
            for o in &e.coinbase.outputs {
                if let Some(c) = counts.get_mut(&o.address) {
                    *c += o.share_ppm as u64;
                }
            }
        }
        shares
            .iter()
            .map(|(a, s)| {
                let gross = (base as u128 * *s as u128 / SHARE_TOTAL as u128) as u64;
                let fee_part = (fees as u128 * *s as u128 / SHARE_TOTAL as u128) as u64;
                damped_amount(gross, counts[a], allowed).saturating_add(fee_part)
            })
            .collect()
    }

    /// Plantilla de bloque para minar sobre `parent`, cobrando todo `miner`: target, coinbase y
    /// Merkle ya correctos; el nonce queda en 0 para que lo busque el minero.
    pub fn build_template(
        &self,
        parent: &Hash32,
        miner: Address,
        timestamp: u64,
        extra: Vec<u8>,
    ) -> Result<Block, ChainError> {
        self.build_template_split(parent, &[(miner, SHARE_TOTAL)], timestamp, extra)
    }

    /// Como `build_template`, con el reparto `shares` (dirección, parte en ppm). Es lo que usará un
    /// pool descentralizado: las partes salen de los shares recientes de su cadena auxiliar.
    pub fn build_template_split(
        &self,
        parent: &Hash32,
        shares: &[(Address, u32)],
        timestamp: u64,
        extra: Vec<u8>,
    ) -> Result<Block, ChainError> {
        self.build_template_full(parent, shares, timestamp, extra, 0, vec![])
    }

    /// Plantilla completa: reparto, comisiones `fees` y las hojas (`full_id`) de las transacciones.
    pub fn build_template_full(
        &self,
        parent: &Hash32,
        shares: &[(Address, u32)],
        timestamp: u64,
        extra: Vec<u8>,
        fees: u64,
        tx_leaves: Vec<Hash32>,
    ) -> Result<Block, ChainError> {
        let p = self.blocks.get(parent).ok_or(ChainError::UnknownParent)?;
        if p.invalid {
            return Err(ChainError::InvalidParent);
        }
        if extra.len() > MAX_COINBASE_EXTRA {
            return Err(ChainError::CoinbaseExtraTooLong(extra.len()));
        }
        if tx_leaves.len() > MAX_BLOCK_TXS {
            return Err(ChainError::TooManyTxs(tx_leaves.len()));
        }
        check_shares(shares)?;
        let height = p.header.height + 1;
        let target = next_target(&self.lwma_window(parent));
        let amounts = self.expected_amounts(parent, height, shares, &target, fees);
        let outputs = shares
            .iter()
            .zip(amounts)
            .map(|((address, share_ppm), amount)| Output { address: *address, share_ppm: *share_ppm, amount })
            .collect();
        let coinbase = Coinbase { height, fees, outputs, extra };
        let mut leaves = Vec::with_capacity(1 + tx_leaves.len());
        leaves.push(coinbase.id());
        leaves.extend_from_slice(&tx_leaves);
        let header = BlockHeader {
            version: HEADER_VERSION,
            height,
            prev_hash: *parent,
            merkle_root: merkle_root(&leaves),
            timestamp,
            target,
            nonce: 0,
        };
        Ok(Block { header, coinbase, tx_leaves })
    }

    /// Valida un bloque y lo incorpora. `now` es el reloj local (s Unix).
    pub fn add_block(
        &mut self,
        block: Block,
        now: u64,
        pow: &mut dyn PowCheck,
    ) -> Result<AddOutcome, ChainError> {
        let id = block.id();
        if self.blocks.contains_key(&id) {
            return Ok(AddOutcome::AlreadyKnown);
        }
        let parent_id = block.header.prev_hash;
        let (parent_height, parent_cum) = {
            let p = self.blocks.get(&parent_id).ok_or(ChainError::UnknownParent)?;
            if p.invalid {
                return Err(ChainError::InvalidParent);
            }
            (p.header.height, p.cum_work)
        };

        // 2. cabecera
        let window = self.lwma_window(&parent_id);
        let parent_info = ParentInfo { height: parent_height, id: parent_id };
        validate_header_cheap(&block.header, &parent_info, &window, now)?;

        // 3. cuerpo
        let cb = &block.coinbase;
        if cb.height != block.header.height {
            return Err(ChainError::BadCoinbaseHeight { expected: block.header.height, got: cb.height });
        }
        if cb.extra.len() > MAX_COINBASE_EXTRA {
            return Err(ChainError::CoinbaseExtraTooLong(cb.extra.len()));
        }
        if block.tx_leaves.len() > MAX_BLOCK_TXS {
            return Err(ChainError::TooManyTxs(block.tx_leaves.len()));
        }
        let shares: Vec<(Address, u32)> = cb.outputs.iter().map(|o| (o.address, o.share_ppm)).collect();
        check_shares(&shares)?; // antes del Merkle: la serialización asume ≤ 64 salidas
        if block.header.merkle_root != block.expected_merkle_root() {
            return Err(ChainError::BadMerkleRoot);
        }
        let expected =
            self.expected_amounts(&parent_id, block.header.height, &shares, &block.header.target, cb.fees);
        for (index, (o, exp)) in cb.outputs.iter().zip(expected).enumerate() {
            if o.amount != exp {
                return Err(ChainError::BadPayout { index, expected: exp, got: o.amount });
            }
        }

        // 4. PoW (lo más caro, al final)
        let seed = self.epoch_seed(&parent_id, block.header.height)?;
        pow.check(&block.header, &seed)?;

        // insertar y decidir la punta
        let cum_work = parent_cum
            .checked_add(block_work(&block.header.target))
            .expect("el trabajo acumulado no desborda 256 bits");
        let old_tip = self.tip;
        let old_work = self.blocks[&old_tip].cum_work;
        let seq = self.next_seq;
        self.next_seq += 1;
        self.blocks.insert(
            id,
            Entry { header: block.header.clone(), coinbase: block.coinbase.clone(), cum_work, seq, invalid: false },
        );

        if cum_work > old_work {
            self.tip = id;
            if parent_id == old_tip {
                self.main.push(id);
                self.main_issued += block.coinbase.reward();
                self.main_fees += block.coinbase.fees;
                Ok(AddOutcome::Extended)
            } else {
                let (detached, attached) = self.path_between(&old_tip, &id);
                for d in &detached {
                    let cb = &self.blocks[d].coinbase;
                    self.main_issued -= cb.reward();
                    self.main_fees -= cb.fees;
                }
                let fork_height = self.blocks[&attached[0]].header.height as usize;
                self.main.truncate(fork_height);
                for a in &attached {
                    let cb = &self.blocks[a].coinbase;
                    self.main_issued += cb.reward();
                    self.main_fees += cb.fees;
                    self.main.push(*a);
                }
                Ok(AddOutcome::Reorg { detached, attached })
            }
        } else {
            Ok(AddOutcome::SideChain)
        }
    }

    /// Camino entre dos puntas: (bloques que salen, de la punta vieja hacia atrás;
    /// bloques que entran, del ancestro común hacia la punta nueva).
    ///
    /// Los dos ids deben existir en la cadena (si no, entra en pánico).
    pub fn path_between(&self, old_tip: &Hash32, new_tip: &Hash32) -> (Vec<Hash32>, Vec<Hash32>) {
        let (mut a, mut b) = (*old_tip, *new_tip);
        let (mut detached, mut attached) = (vec![], vec![]);
        let height = |id: &Hash32| self.blocks[id].header.height;
        while height(&a) > height(&b) {
            detached.push(a);
            a = self.blocks[&a].header.prev_hash;
        }
        while height(&b) > height(&a) {
            attached.push(b);
            b = self.blocks[&b].header.prev_hash;
        }
        while a != b {
            detached.push(a);
            attached.push(b);
            a = self.blocks[&a].header.prev_hash;
            b = self.blocks[&b].header.prev_hash;
        }
        attached.reverse();
        (detached, attached)
    }

    /// Ids de la cadena principal, del génesis a la punta (copia; para recorrer sin copiar usa
    /// `main_ids`).
    pub fn main_chain(&self) -> Vec<Hash32> {
        self.main.clone()
    }

    /// Ids de la cadena principal por altura, sin copiar: `main_ids()[h]` es el bloque de altura `h`.
    pub fn main_ids(&self) -> &[Hash32] {
        &self.main
    }

    /// Id del bloque de la cadena principal a la altura `h`, en O(1).
    pub fn id_at_height(&self, h: u64) -> Option<Hash32> {
        self.main.get(usize::try_from(h).ok()?).copied()
    }

    /// Altura de `id` si pertenece a la cadena principal, en O(1).
    pub fn main_height_of(&self, id: &Hash32) -> Option<u64> {
        let h = self.blocks.get(id)?.header.height;
        (self.id_at_height(h).as_ref() == Some(id)).then_some(h)
    }

    /// Total pagado por los coinbase de la cadena principal (subsidio amortiguado + comisiones).
    pub fn issued_on_main_chain(&self) -> u64 {
        self.main_issued
    }

    /// Comisiones declaradas por los bloques de la cadena principal.
    pub fn fees_on_main_chain(&self) -> u64 {
        self.main_fees
    }

    /// Reconstruye índice y totales desde la punta (solo tras `invalidate`, que es raro).
    fn rebuild_main(&mut self) {
        let mut v: Vec<Hash32> = vec![];
        let (mut issued, mut fees) = (0u64, 0u64);
        let mut cur = self.tip;
        loop {
            v.push(cur);
            let e = &self.blocks[&cur];
            issued += e.coinbase.reward();
            fees += e.coinbase.fees;
            if e.header.height == 0 {
                break;
            }
            cur = e.header.prev_hash;
        }
        v.reverse();
        self.main = v;
        self.main_issued = issued;
        self.main_fees = fees;
    }

    /// Marca un bloque (y todos sus descendientes) como inválido y elige la mejor punta entre los
    /// demás: mayor trabajo acumulado, y a igual trabajo la primera vista. Lo usa el libro mayor
    /// cuando un bloque con PoW válido falla al ejecutarse (comisiones falsas, doble gasto…).
    pub fn invalidate(&mut self, id: &Hash32) -> Result<(), ChainError> {
        if *id == self.genesis || !self.blocks.contains_key(id) {
            return Err(ChainError::CannotInvalidate);
        }
        self.blocks.get_mut(id).unwrap().invalid = true;
        // propagar a los descendientes en una sola pasada por altura creciente
        let mut order: Vec<(u64, Hash32)> = self.blocks.iter().map(|(k, e)| (e.header.height, *k)).collect();
        order.sort();
        for (_, k) in order {
            let parent = self.blocks[&k].header.prev_hash;
            if self.blocks.get(&parent).map_or(false, |p| p.invalid) {
                self.blocks.get_mut(&k).unwrap().invalid = true;
            }
        }
        let mut best: Option<(&Hash32, &Entry)> = None;
        for (k, e) in self.blocks.iter().filter(|(_, e)| !e.invalid) {
            best = match best {
                None => Some((k, e)),
                Some((bk, be)) => {
                    if e.cum_work > be.cum_work || (e.cum_work == be.cum_work && e.seq < be.seq) {
                        Some((k, e))
                    } else {
                        Some((bk, be))
                    }
                }
            };
        }
        self.tip = *best.expect("el génesis nunca se invalida").0;
        self.rebuild_main();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::genesis_block;
    use crate::damper::damped_reward;
    use crate::emission::INITIAL_SUBSIDY;
    use crate::pow_check::SkipPow;
    use armax_pow::consensus::TARGET_BLOCK_TIME;

    const T0: u64 = 1_800_000_000;
    const FAR: u64 = u64::MAX / 4; // `now` muy lejano: estos tests no ejercitan el límite de futuro

    fn addr(n: u8) -> Address {
        Address([n; 32])
    }

    fn new_chain(damper: DamperParams) -> Chain {
        Chain::new(damper, genesis_block(T0, b"test")).unwrap()
    }

    /// Mina (sin PoW real) un hijo de `parent` con `dt` segundos de diferencia y devuelve su id.
    fn extend(chain: &mut Chain, parent: &Hash32, miner: Address, dt: u64) -> Result<Hash32, ChainError> {
        let ts = chain.header(parent).unwrap().timestamp + dt;
        let b = chain.build_template(parent, miner, ts, vec![])?;
        let id = b.id();
        chain.add_block(b, FAR, &mut SkipPow)?;
        Ok(id)
    }

    fn extend_n(chain: &mut Chain, from: &Hash32, miner: Address, dt: u64, n: usize) -> Vec<Hash32> {
        let mut out = vec![];
        let mut cur = *from;
        for _ in 0..n {
            cur = extend(chain, &cur, miner, dt).unwrap();
            out.push(cur);
        }
        out
    }

    #[test]
    fn genesis_checks() {
        let ok = genesis_block(T0, b"x");
        assert!(Chain::new(DamperParams::MAINNET, ok.clone()).is_ok());

        let mut g = ok.clone();
        g.coinbase.outputs.push(Output { address: addr(1), share_ppm: SHARE_TOTAL, amount: 1 });
        g.header.merkle_root = g.expected_merkle_root();
        assert!(matches!(Chain::new(DamperParams::MAINNET, g), Err(ChainError::BadGenesis(_))));

        let mut g = ok.clone();
        g.header.target = g.header.target.shr(1);
        assert!(matches!(Chain::new(DamperParams::MAINNET, g), Err(ChainError::BadGenesis(_))));
    }

    #[test]
    fn linear_chain_grows_and_pays_the_schedule() {
        let mut c = new_chain(DamperParams::MAINNET);
        let g = c.genesis_id();
        let ids = extend_n(&mut c, &g, addr(1), TARGET_BLOCK_TIME, 30);
        assert_eq!(c.tip_height(), 30);
        assert_eq!(c.tip_id(), *ids.last().unwrap());
        assert_eq!(c.issued_on_main_chain(), 30 * INITIAL_SUBSIDY);
        assert_eq!(c.reward_of(&ids[0]), Some(INITIAL_SUBSIDY));
    }

    #[test]
    fn duplicate_and_unknown_parent() {
        let mut c = new_chain(DamperParams::MAINNET);
        let g = c.genesis_id();
        let b = c.build_template(&g, addr(1), T0 + TARGET_BLOCK_TIME, vec![]).unwrap();
        assert_eq!(c.add_block(b.clone(), FAR, &mut SkipPow), Ok(AddOutcome::Extended));
        assert_eq!(c.add_block(b.clone(), FAR, &mut SkipPow), Ok(AddOutcome::AlreadyKnown));

        let mut orphan = b.clone();
        orphan.header.prev_hash = [9u8; 32];
        assert_eq!(c.add_block(orphan, FAR, &mut SkipPow), Err(ChainError::UnknownParent));
    }

    #[test]
    fn rejects_bad_bodies() {
        let mut c = new_chain(DamperParams::MAINNET);
        let g = c.genesis_id();
        let good = c.build_template(&g, addr(1), T0 + TARGET_BLOCK_TIME, vec![]).unwrap();

        // recompensa inflada: el minero intenta cobrar de más
        let mut b = good.clone();
        b.coinbase.outputs[0].amount += 1;
        b.header.merkle_root = b.expected_merkle_root();
        assert!(matches!(
            c.add_block(b, FAR, &mut SkipPow),
            Err(ChainError::BadPayout { index: 0, .. })
        ));

        // recompensa recortada: también se rechaza (la recompensa es exacta)
        let mut b = good.clone();
        b.coinbase.outputs[0].amount -= 1;
        b.header.merkle_root = b.expected_merkle_root();
        assert!(matches!(c.add_block(b, FAR, &mut SkipPow), Err(ChainError::BadPayout { .. })));

        // Merkle que no corresponde
        let mut b = good.clone();
        b.header.merkle_root[0] ^= 1;
        assert_eq!(c.add_block(b, FAR, &mut SkipPow), Err(ChainError::BadMerkleRoot));

        // coinbase con otra altura
        let mut b = good.clone();
        b.coinbase.height = 7;
        b.header.merkle_root = b.expected_merkle_root();
        assert!(matches!(c.add_block(b, FAR, &mut SkipPow), Err(ChainError::BadCoinbaseHeight { .. })));

        // extra demasiado largo
        let mut b = good.clone();
        b.coinbase.extra = vec![0u8; MAX_COINBASE_EXTRA + 1];
        assert!(matches!(c.add_block(b, FAR, &mut SkipPow), Err(ChainError::CoinbaseExtraTooLong(_))));

        // cambiar el minero tras calcular el Merkle: la raíz ya no coincide
        let mut b = good.clone();
        b.coinbase.outputs[0].address = addr(2);
        assert_eq!(c.add_block(b, FAR, &mut SkipPow), Err(ChainError::BadMerkleRoot));

        // el bueno sigue pasando
        assert_eq!(c.add_block(good, FAR, &mut SkipPow), Ok(AddOutcome::Extended));
    }

    #[test]
    fn rejects_header_rule_violations() {
        let mut c = new_chain(DamperParams::MAINNET);
        let g = c.genesis_id();
        let good = c.build_template(&g, addr(1), T0 + TARGET_BLOCK_TIME, vec![]).unwrap();

        let mut b = good.clone();
        b.header.target = b.header.target.shr(1); // el minero se elige un target
        assert!(matches!(
            c.add_block(b, FAR, &mut SkipPow),
            Err(ChainError::Header(HeaderError::TargetMismatch { .. }))
        ));

        // timestamp en el futuro respecto al reloj local
        assert!(matches!(
            c.add_block(good.clone(), T0 - 10_000, &mut SkipPow),
            Err(ChainError::Header(HeaderError::TimestampTooFarInFuture { .. }))
        ));
        assert_eq!(c.add_block(good, FAR, &mut SkipPow), Ok(AddOutcome::Extended));
    }

    #[test]
    fn pow_failure_rejects_and_runs_last() {
        struct Reject;
        impl PowCheck for Reject {
            fn check(&mut self, _: &BlockHeader, _: &[u8; 32]) -> Result<(), HeaderError> {
                Err(HeaderError::InsufficientWork)
            }
        }
        let mut c = new_chain(DamperParams::MAINNET);
        let g = c.genesis_id();
        let b = c.build_template(&g, addr(1), T0 + TARGET_BLOCK_TIME, vec![]).unwrap();
        assert_eq!(
            c.add_block(b.clone(), FAR, &mut Reject),
            Err(ChainError::Header(HeaderError::InsufficientWork))
        );
        assert!(!c.contains(&b.id())); // no se guarda un bloque sin PoW válido

        // un bloque con cuerpo inválido no debe llegar a consultar el PoW
        struct Panics;
        impl PowCheck for Panics {
            fn check(&mut self, _: &BlockHeader, _: &[u8; 32]) -> Result<(), HeaderError> {
                panic!("el PoW no debería ejecutarse con un cuerpo inválido");
            }
        }
        let mut bad = b.clone();
        bad.coinbase.outputs[0].amount += 5;
        bad.header.merkle_root = bad.expected_merkle_root();
        assert!(matches!(c.add_block(bad, FAR, &mut Panics), Err(ChainError::BadPayout { .. })));
    }

    #[test]
    fn damper_reduces_reward_of_an_address_that_dominates_the_window() {
        // Cap diminuto para que el amortiguador actúe con work ≈ 1500: presupuesto = 20·300·1 = 6000.
        let p = DamperParams { window: 20, cap_hps: 1, z: 3 };
        let mut c = new_chain(p);
        let g = c.genesis_id();
        let ids = extend_n(&mut c, &g, addr(1), TARGET_BLOCK_TIME, 16);
        let rewards: Vec<u64> = ids.iter().map(|id| c.reward_of(id).unwrap()).collect();

        assert_eq!(rewards[0], INITIAL_SUBSIDY);
        assert!(rewards.windows(2).all(|w| w[1] <= w[0]), "no debe subir: {rewards:?}");
        let last = *rewards.last().unwrap();
        assert!(last < INITIAL_SUBSIDY, "la dirección dominante debe ser recortada: {rewards:?}");

        // fórmula independiente para el último bloque
        let h = c.header(ids.last().unwrap()).unwrap();
        let allowed = allowed_blocks(&block_work(&h.target), &p);
        assert_eq!(last, damped_reward(INITIAL_SUBSIDY, 16, allowed));
        // lo recortado no se emite
        assert!(c.issued_on_main_chain() < 16 * INITIAL_SUBSIDY);
    }

    #[test]
    fn damper_does_not_touch_miners_who_share_blocks() {
        let p = DamperParams { window: 20, cap_hps: 1, z: 3 };
        let mut c = new_chain(p);
        let mut cur = c.genesis_id();
        for i in 0..16 {
            cur = extend(&mut c, &cur, addr(1 + (i % 4) as u8), TARGET_BLOCK_TIME).unwrap();
            assert_eq!(c.reward_of(&cur), Some(INITIAL_SUBSIDY), "bloque {i}");
        }
    }

    #[test]
    fn damper_window_forgets_old_blocks() {
        let p = DamperParams { window: 20, cap_hps: 1, z: 3 };
        let mut c = new_chain(p);
        let mut cur = c.genesis_id();
        // addr(1) satura la ventana...
        for _ in 0..16 {
            cur = extend(&mut c, &cur, addr(1), TARGET_BLOCK_TIME).unwrap();
        }
        // ...luego mina otro durante una ventana entera; al volver, addr(1) cobra completo otra vez
        for _ in 0..20 {
            cur = extend(&mut c, &cur, addr(2), TARGET_BLOCK_TIME).unwrap();
        }
        cur = extend(&mut c, &cur, addr(1), TARGET_BLOCK_TIME).unwrap();
        assert_eq!(c.reward_of(&cur), Some(INITIAL_SUBSIDY));
    }

    fn split(parts: &[(u8, u32)]) -> Vec<(Address, u32)> {
        parts.iter().map(|(a, s)| (addr(*a), *s)).collect()
    }

    /// Construye y añade un hijo con reparto; devuelve su id.
    fn extend_split(chain: &mut Chain, parent: &Hash32, parts: &[(Address, u32)]) -> Result<Hash32, ChainError> {
        let ts = chain.header(parent).unwrap().timestamp + TARGET_BLOCK_TIME;
        let b = chain.build_template_split(parent, parts, ts, vec![])?;
        let id = b.id();
        chain.add_block(b, FAR, &mut SkipPow)?;
        Ok(id)
    }

    #[test]
    fn split_coinbase_pays_each_address_its_share() {
        let mut c = new_chain(DamperParams::MAINNET);
        let g = c.genesis_id();
        let id = extend_split(&mut c, &g, &split(&[(1, 500_000), (2, 300_000), (3, 200_000)])).unwrap();
        let outs = c.payouts_of(&id).unwrap();
        assert_eq!(outs.len(), 3);
        assert_eq!(outs[0].amount, INITIAL_SUBSIDY / 2);
        assert_eq!(outs[1].amount, INITIAL_SUBSIDY * 3 / 10);
        assert_eq!(outs[2].amount, INITIAL_SUBSIDY / 5);
        assert_eq!(c.reward_of(&id), Some(INITIAL_SUBSIDY));
        assert_eq!(c.issued_on_main_chain(), INITIAL_SUBSIDY);
    }

    #[test]
    fn rounding_dust_is_not_minted() {
        let mut c = new_chain(DamperParams::MAINNET);
        let g = c.genesis_id();
        // 3 partes iguales de 333,333/333,333/333,334 ppm: la suma bruta puede quedar bajo el subsidio
        let id = extend_split(&mut c, &g, &split(&[(1, 333_333), (2, 333_333), (3, 333_334)])).unwrap();
        let total = c.reward_of(&id).unwrap();
        assert!(total <= INITIAL_SUBSIDY && INITIAL_SUBSIDY - total < 3, "total={total}");
    }

    #[test]
    fn rejects_malformed_splits() {
        let mut c = new_chain(DamperParams::MAINNET);
        let g = c.genesis_id();
        let t = |c: &Chain, p: &[(Address, u32)]| c.build_template_split(&g, p, T0 + TARGET_BLOCK_TIME, vec![]);
        // al construir
        assert_eq!(t(&c, &[]).unwrap_err(), ChainError::BadCoinbaseOutputs("sin salidas"));
        assert_eq!(
            t(&c, &split(&[(1, 600_000), (2, 300_000)])).unwrap_err(),
            ChainError::BadCoinbaseOutputs("las partes no suman 1,000,000")
        );
        assert_eq!(
            t(&c, &split(&[(1, 500_000), (1, 500_000)])).unwrap_err(),
            ChainError::BadCoinbaseOutputs("dirección repetida")
        );
        assert_eq!(
            t(&c, &split(&[(1, 999_500), (2, 500)])).unwrap_err(),
            ChainError::BadCoinbaseOutputs("parte por debajo del mínimo")
        );
        let many: Vec<(Address, u32)> = (0..65u8).map(|i| (addr(i + 1), 1_000_000 / 65)).collect();
        assert_eq!(t(&c, &many).unwrap_err(), ChainError::BadCoinbaseOutputs("demasiadas salidas"));

        // 64 salidas distintas, exactas: válido
        let mut ok64: Vec<(Address, u32)> = (0..64u8).map(|i| (addr(i + 1), 15_625)).collect();
        assert_eq!(ok64.iter().map(|(_, s)| *s as u64).sum::<u64>(), SHARE_TOTAL as u64);
        let b = c.build_template_split(&g, &ok64, T0 + TARGET_BLOCK_TIME, vec![]).unwrap();
        assert_eq!(c.add_block(b, FAR, &mut SkipPow), Ok(AddOutcome::Extended));
        ok64.clear();

        // al validar un bloque ajeno con el cuerpo manipulado (65 salidas no debe causar pánico)
        let g2 = c.genesis_id();
        let good = c.build_template_split(&g2, &split(&[(1, 500_000), (2, 500_000)]), T0 + TARGET_BLOCK_TIME, vec![]).unwrap();
        let mut b = good.clone();
        b.coinbase.outputs = (0..65u8)
            .map(|i| Output { address: addr(i + 1), share_ppm: 15_384, amount: 0 })
            .collect();
        assert_eq!(c.add_block(b, FAR, &mut SkipPow), Err(ChainError::BadCoinbaseOutputs("demasiadas salidas")));
        let mut b = good.clone();
        b.coinbase.outputs[1].address = b.coinbase.outputs[0].address;
        assert_eq!(c.add_block(b, FAR, &mut SkipPow), Err(ChainError::BadCoinbaseOutputs("dirección repetida")));
        let mut b = good.clone();
        b.coinbase.outputs.clear();
        assert_eq!(c.add_block(b, FAR, &mut SkipPow), Err(ChainError::BadCoinbaseOutputs("sin salidas")));
        // el bueno pasa
        assert_eq!(c.add_block(good, FAR, &mut SkipPow), Ok(AddOutcome::SideChain));
    }

    #[test]
    fn wrong_amount_in_second_output_is_located() {
        let mut c = new_chain(DamperParams::MAINNET);
        let g = c.genesis_id();
        let mut b = c
            .build_template_split(&g, &split(&[(1, 500_000), (2, 500_000)]), T0 + TARGET_BLOCK_TIME, vec![])
            .unwrap();
        b.coinbase.outputs[1].amount += 1;
        b.header.merkle_root = b.expected_merkle_root();
        assert!(matches!(c.add_block(b, FAR, &mut SkipPow), Err(ChainError::BadPayout { index: 1, .. })));
    }

    #[test]
    fn damper_is_proportional_per_address_in_a_split() {
        // Cap diminuto: allowed pequeño. addr(1) domina la ventana; addr(2) cobra un 5 % cada vez.
        let p = DamperParams { window: 20, cap_hps: 1, z: 3 };
        let mut c = new_chain(p);
        let mut cur = c.genesis_id();
        let parts = split(&[(1, 950_000), (2, 50_000)]);
        let mut last = cur;
        for _ in 0..16 {
            cur = extend_split(&mut c, &cur, &parts).unwrap();
            last = cur;
        }
        let outs = c.payouts_of(&last).unwrap().to_vec();
        let h = c.header(&last).unwrap();
        let allowed = allowed_blocks(&block_work(&h.target), &p);
        // addr(1) lleva 16 · 0.95 = 15.2 bloques en la ventana; addr(2) lleva 0.8
        let gross1 = INITIAL_SUBSIDY * 950_000 / 1_000_000;
        let gross2 = INITIAL_SUBSIDY * 50_000 / 1_000_000;
        assert_eq!(outs[0].amount, damped_amount(gross1, 16 * 950_000, allowed));
        assert_eq!(outs[1].amount, damped_amount(gross2, 16 * 50_000, allowed));
        assert!(outs[0].amount < gross1, "la dirección dominante debe recortarse: {outs:?} allowed={allowed}");
        assert_eq!(outs[1].amount, gross2, "la parte pequeña no debe recortarse");
    }

    #[test]
    fn many_small_shares_beat_one_big_address_under_the_cap() {
        // 20 direcciones con 5 % cada una (un pool descentralizado de 20 miembros) cobran todo,
        // mientras que una sola dirección con el 100 % del mismo hashrate se recorta.
        let p = DamperParams { window: 20, cap_hps: 1, z: 3 };
        let mut pool = new_chain(p);
        let mut solo = new_chain(p);
        let (mut a, mut b) = (pool.genesis_id(), solo.genesis_id());
        let parts: Vec<(Address, u32)> = (1..=20u8).map(|i| (addr(i), 50_000)).collect();
        for _ in 0..16 {
            a = extend_split(&mut pool, &a, &parts).unwrap();
            b = extend(&mut solo, &b, addr(1), TARGET_BLOCK_TIME).unwrap();
        }
        assert_eq!(pool.reward_of(&a), Some(INITIAL_SUBSIDY));
        assert!(solo.reward_of(&b).unwrap() < INITIAL_SUBSIDY);
        assert_eq!(pool.issued_on_main_chain(), 16 * INITIAL_SUBSIDY);
    }

    #[test]
    fn single_output_behaves_exactly_like_the_old_single_miner_rule() {
        // regresión: con una salida del 100 % el recorte coincide con damped_reward(base, count, allowed)
        let p = DamperParams { window: 20, cap_hps: 1, z: 3 };
        let mut c = new_chain(p);
        let g = c.genesis_id();
        let ids = extend_n(&mut c, &g, addr(1), TARGET_BLOCK_TIME, 16);
        for (i, id) in ids.iter().enumerate() {
            let h = c.header(id).unwrap();
            let allowed = allowed_blocks(&block_work(&h.target), &p);
            assert_eq!(
                c.reward_of(id),
                Some(crate::damper::damped_reward(INITIAL_SUBSIDY, (i + 1) as u64, allowed)),
                "bloque {}",
                i + 1
            );
        }
    }

    fn full(chain: &Chain, parent: &Hash32, parts: &[(Address, u32)], fees: u64, leaves: Vec<Hash32>) -> Block {
        let ts = chain.header(parent).unwrap().timestamp + TARGET_BLOCK_TIME;
        chain.build_template_full(parent, parts, ts, vec![], fees, leaves).unwrap()
    }

    #[test]
    fn fees_are_split_by_share_and_never_damped() {
        // Con un cap diminuto el subsidio se recorta, pero las comisiones se pagan completas.
        let p = DamperParams { window: 20, cap_hps: 1, z: 3 };
        let mut c = new_chain(p);
        let mut cur = c.genesis_id();
        for _ in 0..16 {
            cur = extend(&mut c, &cur, addr(1), TARGET_BLOCK_TIME).unwrap();
        }
        let sub_only = c.reward_of(&cur).unwrap();
        assert!(sub_only < INITIAL_SUBSIDY, "el escenario necesita amortiguación");
        let parts = split(&[(1, 750_000), (2, 250_000)]);
        let b = full(&c, &cur, &parts, 1_000, vec![]);
        let id = b.id();
        c.add_block(b, FAR, &mut SkipPow).unwrap();
        let outs = c.payouts_of(&id).unwrap();
        // addr(2) no está amortiguada: 25 % del subsidio + 25 % de las comisiones
        assert_eq!(outs[1].amount, INITIAL_SUBSIDY / 4 + 250);
        // addr(1): subsidio recortado + 75 % de las comisiones
        let h = c.header(&id).unwrap();
        let allowed = allowed_blocks(&block_work(&h.target), &p);
        let gross1 = INITIAL_SUBSIDY * 750_000 / 1_000_000;
        assert_eq!(outs[0].amount, damped_amount(gross1, 16 * 1_000_000 + 750_000, allowed) + 750);
        assert_eq!(c.coinbase_of(&id).unwrap().fees, 1_000);
        assert_eq!(c.fees_on_main_chain(), 1_000);
    }

    #[test]
    fn declared_fees_must_match_the_amounts() {
        let mut c = new_chain(DamperParams::MAINNET);
        let g = c.genesis_id();
        let mut b = full(&c, &g, &split(&[(1, 1_000_000)]), 500, vec![]);
        b.coinbase.fees = 600; // declara más comisiones que las usadas para calcular los montos
        b.header.merkle_root = b.expected_merkle_root();
        assert!(matches!(c.add_block(b, FAR, &mut SkipPow), Err(ChainError::BadPayout { .. })));
        // sin comisiones declaradas pero con un monto de más
        let mut b = full(&c, &g, &split(&[(1, 1_000_000)]), 0, vec![]);
        b.coinbase.outputs[0].amount += 500;
        b.header.merkle_root = b.expected_merkle_root();
        assert!(matches!(c.add_block(b, FAR, &mut SkipPow), Err(ChainError::BadPayout { .. })));
    }

    #[test]
    fn tx_leaves_are_committed_by_the_merkle_root_and_bounded() {
        let mut c = new_chain(DamperParams::MAINNET);
        let g = c.genesis_id();
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let good = full(&c, &g, &split(&[(1, 1_000_000)]), 0, leaves.clone());
        assert_eq!(good.tx_leaves, leaves);

        let mut b = good.clone();
        b.tx_leaves[1] = [9u8; 32];
        assert_eq!(c.add_block(b, FAR, &mut SkipPow), Err(ChainError::BadMerkleRoot));
        let mut b = good.clone();
        b.tx_leaves.pop();
        assert_eq!(c.add_block(b, FAR, &mut SkipPow), Err(ChainError::BadMerkleRoot));
        let mut b = good.clone();
        b.tx_leaves.swap(0, 2);
        assert_eq!(c.add_block(b, FAR, &mut SkipPow), Err(ChainError::BadMerkleRoot));

        // demasiadas transacciones: se rechaza antes de calcular el Merkle
        let mut b = good.clone();
        b.tx_leaves = vec![[0u8; 32]; MAX_BLOCK_TXS + 1];
        assert_eq!(c.add_block(b, FAR, &mut SkipPow), Err(ChainError::TooManyTxs(MAX_BLOCK_TXS + 1)));
        assert_eq!(
            c.build_template_full(&g, &split(&[(1, 1_000_000)]), T0 + 1, vec![], 0, vec![[0u8; 32]; MAX_BLOCK_TXS + 1])
                .unwrap_err(),
            ChainError::TooManyTxs(MAX_BLOCK_TXS + 1)
        );
        assert_eq!(c.add_block(good, FAR, &mut SkipPow), Ok(AddOutcome::Extended));
        // el máximo exacto sí cabe
        let g2 = c.tip_id();
        let max = full(&c, &g2, &split(&[(1, 1_000_000)]), 0, vec![[7u8; 32]; MAX_BLOCK_TXS]);
        assert_eq!(c.add_block(max, FAR, &mut SkipPow), Ok(AddOutcome::Extended));
    }

    #[test]
    fn invalidate_picks_the_best_remaining_tip_and_blocks_descendants() {
        let mut c = new_chain(DamperParams::MAINNET);
        let g = c.genesis_id();
        let fork = *extend_n(&mut c, &g, addr(1), TARGET_BLOCK_TIME, 2).last().unwrap();
        let a = extend_n(&mut c, &fork, addr(2), TARGET_BLOCK_TIME, 3); // rama A (llegó primero)
        let b = extend_n(&mut c, &fork, addr(3), TARGET_BLOCK_TIME, 2); // rama B (menos trabajo)
        assert_eq!(c.tip_id(), a[2]);

        // invalidar el primer bloque de A: la punta pasa a B y A entera queda inválida
        c.invalidate(&a[0]).unwrap();
        assert!(a.iter().all(|id| c.is_invalid(id)));
        assert!(b.iter().all(|id| !c.is_invalid(id)));
        assert_eq!(c.tip_id(), b[1]);

        // no se acepta nada encima de un bloque inválido
        let ts = c.header(&a[2]).unwrap().timestamp + TARGET_BLOCK_TIME;
        let on_invalid = Block { ..c.build_template(&b[1], addr(9), ts, vec![]).unwrap() };
        let mut orphan = on_invalid.clone();
        orphan.header.prev_hash = a[2];
        assert_eq!(c.add_block(orphan, FAR, &mut SkipPow), Err(ChainError::InvalidParent));
        assert_eq!(c.build_template(&a[2], addr(9), ts, vec![]).unwrap_err(), ChainError::InvalidParent);

        // el génesis y los desconocidos no se pueden invalidar
        assert_eq!(c.invalidate(&g), Err(ChainError::CannotInvalidate));
        assert_eq!(c.invalidate(&[0xee; 32]), Err(ChainError::CannotInvalidate));

        // la cadena sigue creciendo sobre B
        let next = extend(&mut c, &b[1], addr(4), TARGET_BLOCK_TIME).unwrap();
        assert_eq!(c.tip_id(), next);
    }

    #[test]
    fn invalidating_a_side_branch_keeps_the_tip_and_ties_go_to_the_first_seen() {
        let mut c = new_chain(DamperParams::MAINNET);
        let g = c.genesis_id();
        let fork = *extend_n(&mut c, &g, addr(1), TARGET_BLOCK_TIME, 2).last().unwrap();
        let first = extend(&mut c, &fork, addr(2), TARGET_BLOCK_TIME).unwrap();
        let ts = c.header(&fork).unwrap().timestamp + TARGET_BLOCK_TIME;
        let rival = c.build_template(&fork, addr(9), ts, vec![]).unwrap();
        let rival_id = rival.id();
        c.add_block(rival, FAR, &mut SkipPow).unwrap(); // mismo trabajo, llegó después
        assert_eq!(c.tip_id(), first);
        c.invalidate(&rival_id).unwrap();
        assert_eq!(c.tip_id(), first);
        // ahora al revés: invalidar la punta devuelve la punta al rival
        let mut c2 = new_chain(DamperParams::MAINNET);
        let g2 = c2.genesis_id();
        let f2 = *extend_n(&mut c2, &g2, addr(1), TARGET_BLOCK_TIME, 2).last().unwrap();
        let first2 = extend(&mut c2, &f2, addr(2), TARGET_BLOCK_TIME).unwrap();
        let ts2 = c2.header(&f2).unwrap().timestamp + TARGET_BLOCK_TIME;
        let rival2 = c2.build_template(&f2, addr(9), ts2, vec![]).unwrap();
        let rival2_id = rival2.id();
        c2.add_block(rival2, FAR, &mut SkipPow).unwrap();
        c2.invalidate(&first2).unwrap();
        assert_eq!(c2.tip_id(), rival2_id);
    }

    #[test]
    fn heavier_branch_wins_even_if_shorter() {
        let mut c = new_chain(DamperParams::MAINNET);
        let g = c.genesis_id();
        let fork = *extend_n(&mut c, &g, addr(1), TARGET_BLOCK_TIME, 5).last().unwrap();

        // Rama B: 8 bloques a ritmo normal (dificultad estable)
        let b = extend_n(&mut c, &fork, addr(3), TARGET_BLOCK_TIME, 8);
        assert_eq!(c.tip_id(), *b.last().unwrap());

        // Rama A: bloques de 1 s => LWMA sube la dificultad de golpe y cada bloque pesa más.
        let mut a: Vec<Hash32> = vec![];
        let mut outcomes: Vec<AddOutcome> = vec![];
        let mut cur = fork;
        for _ in 0..6 {
            let ts = c.header(&cur).unwrap().timestamp + 1;
            let blk = c.build_template(&cur, addr(2), ts, vec![]).unwrap();
            cur = blk.id();
            a.push(cur);
            outcomes.push(c.add_block(blk, FAR, &mut SkipPow).unwrap());
        }
        let work_a = c.cumulative_work(a.last().unwrap()).unwrap();
        let work_b = c.cumulative_work(b.last().unwrap()).unwrap();
        // el escenario es el que queremos probar: A es MÁS CORTA pero pesa MÁS
        assert!(a.len() < b.len());
        assert!(work_a > work_b, "el escenario no cumple: A={work_a:?} B={work_b:?}");

        assert_eq!(c.tip_id(), *a.last().unwrap(), "debe ganar la de más trabajo, no la más larga");
        // Secuencia esperada: SideChain... (A aún pesa menos), UN Reorg en el bloque que supera
        // a B, y Extended en los siguientes (ya extienden la nueva punta).
        let k = outcomes
            .iter()
            .position(|o| matches!(o, AddOutcome::Reorg { .. }))
            .expect("debe haber una reorganización");
        assert!(k > 0, "A no puede pesar más que B con un solo bloque");
        assert!(outcomes[..k].iter().all(|o| *o == AddOutcome::SideChain));
        assert!(outcomes[k + 1..].iter().all(|o| *o == AddOutcome::Extended));
        // en el bloque k de A: sale toda B (de la punta hacia atrás) y entra A[0..=k] en orden
        let mut b_rev = b.clone();
        b_rev.reverse();
        assert_eq!(
            outcomes[k],
            AddOutcome::Reorg { detached: b_rev, attached: a[..=k].to_vec() }
        );
    }

    #[test]
    fn equal_work_keeps_first_seen_tip() {
        let mut c = new_chain(DamperParams::MAINNET);
        let g = c.genesis_id();
        let fork = *extend_n(&mut c, &g, addr(1), TARGET_BLOCK_TIME, 3).last().unwrap();
        let first = extend(&mut c, &fork, addr(2), TARGET_BLOCK_TIME).unwrap();
        assert_eq!(c.tip_id(), first);

        // otro hijo del mismo padre con el mismo trabajo: queda en rama lateral
        let ts = c.header(&fork).unwrap().timestamp + TARGET_BLOCK_TIME;
        let rival = c.build_template(&fork, addr(9), ts, vec![]).unwrap();
        assert_ne!(rival.id(), first);
        assert_eq!(c.add_block(rival, FAR, &mut SkipPow), Ok(AddOutcome::SideChain));
        assert_eq!(c.tip_id(), first);
    }

    #[test]
    fn longer_equal_difficulty_branch_takes_over_via_reorg() {
        let mut c = new_chain(DamperParams::MAINNET);
        let g = c.genesis_id();
        let fork = *extend_n(&mut c, &g, addr(1), TARGET_BLOCK_TIME, 2).last().unwrap();
        let a = extend_n(&mut c, &fork, addr(2), TARGET_BLOCK_TIME, 2);
        let b = extend_n(&mut c, &fork, addr(3), TARGET_BLOCK_TIME, 3);
        assert_eq!(c.tip_id(), *b.last().unwrap());
        assert_eq!(c.main_chain().len(), 2 + 3 + 1);
        assert!(!c.main_chain().contains(&a[0]));
    }

    #[test]
    fn epoch_seed_comes_from_the_ancestor_at_the_agreed_height() {
        use armax_pow::consensus::{EPOCH_LAG, EPOCH_LENGTH};
        let mut c = new_chain(DamperParams::MAINNET);
        let g = c.genesis_id();
        // época 0: semilla fija
        assert_eq!(c.epoch_seed(&g, 1).unwrap(), genesis_epoch_seed());

        // para la altura EPOCH_LENGTH (primera de la época 1) la semilla es el bloque EPOCH_LENGTH - LAG
        let ids = extend_n(&mut c, &g, addr(1), TARGET_BLOCK_TIME, EPOCH_LENGTH as usize - 1);
        let tip = *ids.last().unwrap(); // altura EPOCH_LENGTH - 1
        let seed = c.epoch_seed(&tip, EPOCH_LENGTH).unwrap();
        let seed_block = ids[(EPOCH_LENGTH - EPOCH_LAG) as usize - 1]; // altura EPOCH_LENGTH - LAG
        assert_eq!(c.header(&seed_block).unwrap().height, EPOCH_LENGTH - EPOCH_LAG);
        assert_eq!(seed, seed_block);
    }

    #[test]
    fn height_index_and_totals_follow_extensions_reorgs_and_invalidation() {
        let mut c = new_chain(DamperParams::MAINNET);
        let g = c.genesis_id();
        let check = |c: &Chain| {
            // el índice coincide con el recorrido por prev_hash y los totales con la suma directa
            let mut walk = vec![];
            let mut cur = c.tip_id();
            loop {
                walk.push(cur);
                let h = c.header(&cur).unwrap();
                if h.height == 0 {
                    break;
                }
                cur = h.prev_hash;
            }
            walk.reverse();
            assert_eq!(c.main_ids(), &walk[..]);
            assert_eq!(c.main_chain(), walk);
            let issued: u64 = walk.iter().map(|id| c.reward_of(id).unwrap()).sum();
            let fees: u64 = walk.iter().map(|id| c.coinbase_of(id).unwrap().fees).sum();
            assert_eq!(c.issued_on_main_chain(), issued);
            assert_eq!(c.fees_on_main_chain(), fees);
            for (h, id) in walk.iter().enumerate() {
                assert_eq!(c.id_at_height(h as u64), Some(*id));
                assert_eq!(c.main_height_of(id), Some(h as u64));
            }
            assert_eq!(c.id_at_height(walk.len() as u64), None);
        };
        check(&c);
        let a = extend_n(&mut c, &g, addr(1), TARGET_BLOCK_TIME, 4);
        check(&c);
        // rama lateral más lenta (bloques más separados = menos trabajo por bloque no, pero más largos)
        let b = extend_n(&mut c, &a[0], addr(2), TARGET_BLOCK_TIME, 6); // supera a la principal → reorg
        check(&c);
        assert_eq!(c.tip_id(), *b.last().unwrap());
        assert_eq!(c.main_height_of(&a[3]), None, "un bloque de la rama vieja ya no está en el índice");
        assert_eq!(c.main_height_of(&a[0]), Some(1));
        // invalidar un bloque a mitad de la rama ganadora devuelve la punta a la otra rama
        c.invalidate(&b[2]).unwrap();
        check(&c);
        assert_eq!(c.main_height_of(&b[3]), None);
    }

    // ------------------------------------------------------------ cabeceras sin cuerpos

    fn headers_of(c: &Chain, ids: &[Hash32]) -> Vec<BlockHeader> {
        ids.iter().map(|id| c.header(id).unwrap().clone()).collect()
    }

    /// Dos cadenas con el mismo génesis: `long` con `n` bloques y `short` con los primeros `k`.
    fn long_and_short(n: usize, k: usize) -> (Chain, Chain, Vec<Hash32>) {
        let mut long = new_chain(DamperParams::MAINNET);
        let g = long.genesis_id();
        let ids = extend_n(&mut long, &g, addr(1), TARGET_BLOCK_TIME, n);
        let mut short = new_chain(DamperParams::MAINNET);
        extend_n(&mut short, &g, addr(1), TARGET_BLOCK_TIME, k);
        assert_eq!(short.tip_id(), ids[k - 1]);
        (long, short, ids)
    }

    #[test]
    fn validated_headers_report_the_work_of_the_branch_without_bodies() {
        let (long, short, ids) = long_and_short(12, 5);
        let hs = headers_of(&long, &ids[5..]);
        let run = short.validate_headers(&hs, FAR, &mut SkipPow).unwrap();
        assert_eq!(run.fork_point, ids[4]);
        assert_eq!(run.new_ids, ids[5..].to_vec());
        assert_eq!(run.tip_height, 12);
        assert_eq!(run.work, long.cumulative_work(&ids[11]).unwrap());
        assert!(run.work > short.tip_work());
        // validar no modifica la cadena
        assert_eq!(short.tip_height(), 5);
        assert!(!short.contains(&ids[5]));
        // un prefijo que ya es nuestro se salta
        let hs = headers_of(&long, &ids[2..]);
        let run = short.validate_headers(&hs, FAR, &mut SkipPow).unwrap();
        assert_eq!(run.fork_point, ids[4]);
        assert_eq!(run.new_ids, ids[5..].to_vec());
        // y los cuerpos que llegan después entran sin problema
        assert_eq!(run.work, long.cumulative_work(&ids[11]).unwrap());
    }

    #[test]
    fn header_runs_reject_broken_links_unknown_parents_and_empty_batches() {
        let (long, short, ids) = long_and_short(12, 5);
        let mut hs = headers_of(&long, &ids[5..]);
        hs.swap(1, 2);
        assert_eq!(short.validate_headers(&hs, FAR, &mut SkipPow), Err(ChainError::HeadersNotLinked));
        // salto: falta una cabecera intermedia
        let mut hs = headers_of(&long, &ids[5..]);
        hs.remove(1);
        assert_eq!(short.validate_headers(&hs, FAR, &mut SkipPow), Err(ChainError::HeadersNotLinked));
        // empieza más allá de lo que conocemos
        let hs = headers_of(&long, &ids[7..]);
        assert_eq!(short.validate_headers(&hs, FAR, &mut SkipPow), Err(ChainError::UnknownParent));
        assert_eq!(short.validate_headers(&[], FAR, &mut SkipPow), Err(ChainError::UnknownParent));
        // un conocido después de uno nuevo no vale
        let mut hs = headers_of(&long, &ids[5..8]);
        hs.push(long.header(&ids[2]).unwrap().clone());
        assert_eq!(short.validate_headers(&hs, FAR, &mut SkipPow), Err(ChainError::HeadersNotLinked));
    }

    #[test]
    fn header_rules_and_pow_are_enforced_on_every_header() {
        let (long, short, ids) = long_and_short(12, 5);
        // PoW falso en cualquier posición del lote
        struct RejectAt(usize, usize);
        impl PowCheck for RejectAt {
            fn check(&mut self, _: &BlockHeader, _: &[u8; 32]) -> Result<(), HeaderError> {
                self.1 += 1;
                if self.1 == self.0 {
                    Err(HeaderError::InsufficientWork)
                } else {
                    Ok(())
                }
            }
        }
        let hs = headers_of(&long, &ids[5..]);
        for pos in 1..=hs.len() {
            assert_eq!(
                short.validate_headers(&hs, FAR, &mut RejectAt(pos, 0)),
                Err(ChainError::Header(HeaderError::InsufficientWork)),
                "posición {pos}"
            );
        }
        // target distinto del que dicta LWMA (en la última cabecera, con el enlace intacto)
        let mut bad = hs.clone();
        let last = bad.last_mut().unwrap();
        last.target = last.target.checked_add(U256::from_u64(1)).unwrap_or(last.target);
        assert!(matches!(short.validate_headers(&bad, FAR, &mut SkipPow), Err(ChainError::Header(_))));
        // timestamp en el futuro respecto a `now`
        assert!(matches!(
            short.validate_headers(&hs, hs[0].timestamp - 100_000, &mut SkipPow),
            Err(ChainError::Header(_))
        ));
        // la rama pasa por un bloque inválido
        let mut inv = new_chain(DamperParams::MAINNET);
        let g = inv.genesis_id();
        let a = extend_n(&mut inv, &g, addr(1), TARGET_BLOCK_TIME, 5);
        inv.invalidate(&a[4]).unwrap();
        assert_eq!(inv.validate_headers(&hs, FAR, &mut SkipPow), Err(ChainError::InvalidParent));
    }

    #[test]
    fn header_only_validation_uses_the_same_epoch_seeds_as_full_blocks() {
        use armax_pow::consensus::EPOCH_LENGTH;
        // semillas que ve el PoW al añadir bloques completos…
        struct Spy(Vec<[u8; 32]>);
        impl PowCheck for Spy {
            fn check(&mut self, _: &BlockHeader, seed: &[u8; 32]) -> Result<(), HeaderError> {
                self.0.push(*seed);
                Ok(())
            }
        }
        let n = EPOCH_LENGTH as usize + 8; // cruza la frontera de la época 1
        let k = EPOCH_LENGTH as usize - 100; // la cadena corta ya pasó la altura que siembra la época 1
        let mut long = new_chain(DamperParams::MAINNET);
        let g = long.genesis_id();
        let mut ids = vec![];
        let mut full_seeds = Spy(vec![]);
        let mut parent = g;
        for _ in 0..n {
            let ts = long.header(&parent).unwrap().timestamp + TARGET_BLOCK_TIME;
            let b = long.build_template(&parent, addr(1), ts, vec![]).unwrap();
            let id = b.id();
            long.add_block(b, FAR, &mut full_seeds).unwrap();
            ids.push(id);
            parent = id;
        }
        let mut short = new_chain(DamperParams::MAINNET);
        extend_n(&mut short, &g, addr(1), TARGET_BLOCK_TIME, k);
        // …y las que ve al validar solo cabeceras con la cadena corta como base
        let mut hdr_seeds = Spy(vec![]);
        let hs = headers_of(&long, &ids[k..]);
        let run = short.validate_headers(&hs, FAR, &mut hdr_seeds).unwrap();
        assert_eq!(run.work, long.cumulative_work(ids.last().unwrap()).unwrap());
        assert_eq!(hdr_seeds.0, full_seeds.0[k..].to_vec());
        assert_ne!(hdr_seeds.0.first(), hdr_seeds.0.last(), "debe haberse cruzado una época");
    }
}
