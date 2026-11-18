//! Máquina de estados del nodo (sin E/S).
//!
//! El transporte entrega `Event`s con la hora actual (`now`, segundos) y ejecuta las `Action`s
//! que devuelve `Node::handle`. El nodo es dueño del libro mayor, el mempool y (opcional) el
//! almacenamiento; toda la lógica de red vive aquí.
//!
//! # Decisiones de diseño
//! * **Teléfonos salientes, servidores entrantes.** Un nodo con `serve = false` rechaza
//!   conexiones entrantes y solo marca como "dirección alcanzable" las que él mismo marcó a mano.
//!   Solo las direcciones con el bit `SERVICE_SERVE` entran en la libreta.
//! * **Sincronización cabeceras-primero.** Se piden las cabeceras de la cadena principal del par
//!   (`GetHeaders`, 124 B por bloque) desde el punto de bifurcación y se **validan sin cuerpos**
//!   (enlace, LWMA, tiempo, PoW; ver `armax_chain::HeaderValidator`). Solo las cabeceras que pasan
//!   dan lugar a peticiones de cuerpos, así que un par no puede hacernos descargar bloques de una
//!   cadena sin el trabajo que dice: o el trabajo es real o se le veta antes de bajar nada. El PoW
//!   de una cabecera ya validada no se repite al llegar su bloque. Como cada cabecera cuesta una
//!   ejecución de la VM, la validación se reparte en pasos de `headers_per_step` por evento/tick
//!   para no bloquear el nodo. Solo se sincroniza con un par a la vez, y solo si anuncia más
//!   trabajo acumulado que el nuestro.
//! * **Nada no pedido.** Los bloques y transacciones solo se aceptan si los pedimos; así un par
//!   no puede empujarnos trabajo (CPU de PoW y firmas) a su antojo.
//! * **Castigos.** Cada par acumula puntos de mala conducta; al llegar a `ban_threshold` se
//!   desconecta y se veta su IP `ban_seconds`. Un bloque inválido (PoW, Merkle, ejecución) veta
//!   de inmediato. El desfase de reloj (timestamp futuro) no se castiga.
//! * **Límites de ritmo** por par (cubo de fichas) y de peticiones en vuelo.
//! * **Sharechain (P2Pool, opcional).** Con `enable_sharechain` el nodo valida y retransmite shares
//!   (`InvShares` → `GetShareChain` → `Shares`) solo con pares que anuncian `SERVICE_SHARES`. Igual
//!   que con los bloques, **nada no pedido**: un lote de shares solo vale como respuesta a nuestra
//!   petición (una por par a la vez). Cada share cuesta una ejecución de la VM, así que se encolan y
//!   se validan `shares_per_step` por evento/tick. Un share cuyo anterior o bloque padre no
//!   conocemos es un **huérfano**: se retiene (acotado, con caducidad), se pide lo que falta y se
//!   reintenta cuando llega; no se castiga. Un share inválido con todo su contexto conocido veta al
//!   par. Si un share cumple también el target del bloque, se publica como bloque.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use armax_chain::{AddOutcome, ChainError, FullPow, HeaderValidator, PowCheck, SharePowCheck};
use armax_keys::tx::Transaction;
use armax_ledger::{FullBlock, Ledger, LedgerError};
use armax_mempool::{AddResult, Mempool, MempoolError};
use armax_pow::{BlockHeader, HeaderError, U256};
use armax_share::{AddShare, Share, ShareChain, ShareError, ShareLoadReport, ShareParams, ShareStore};
use armax_store::{Store, StoreError};

use crate::codec::*;

pub type PeerId = u64;

#[derive(Debug)]
pub enum Event {
    Connected { peer: PeerId, addr: NetAddr, inbound: bool },
    ConnectFailed(NetAddr),
    Disconnected(PeerId),
    Message(PeerId, Message),
    Tick,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Connect(NetAddr),
    Send(PeerId, Message),
    Disconnect(PeerId),
}

#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub max_outbound: usize,
    pub max_inbound: usize,
    /// Acepta conexiones entrantes y sirve bloques (nodo "de servicio").
    pub serve: bool,
    pub listen_port: u16,
    /// Dirección pública propia, si se conoce: se anuncia a los pares.
    pub external_addr: Option<NetAddr>,
    pub seeds: Vec<NetAddr>,
    pub handshake_timeout: u64,
    pub ping_interval: u64,
    pub pong_timeout: u64,
    pub idle_timeout: u64,
    pub block_timeout: u64,
    /// Plazo para que el par conteste a `GetHeaders`.
    pub ids_timeout: u64,
    /// Cabeceras que se validan por paso (cada una cuesta una ejecución de la VM).
    pub headers_per_step: usize,
    /// Shares que se validan por paso (cada uno cuesta una ejecución de la VM).
    pub shares_per_step: usize,
    pub ban_seconds: u64,
    pub ban_threshold: u32,
    pub connect_backoff: u64,
    pub max_inflight_blocks: usize,
    pub max_addrbook: usize,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            max_outbound: 8,
            max_inbound: 16,
            serve: false,
            listen_port: 0,
            external_addr: None,
            seeds: vec![],
            handshake_timeout: 30,
            ping_interval: 120,
            pong_timeout: 60,
            idle_timeout: 1_200,
            block_timeout: 120,
            ids_timeout: 60,
            headers_per_step: 4,
            shares_per_step: 2,
            ban_seconds: 86_400,
            ban_threshold: 100,
            connect_backoff: 60,
            max_inflight_blocks: 16,
            max_addrbook: 1_000,
        }
    }
}

/// Segundos sin ningún evento (el reloj da un tic cada ~1 s) tras los cuales se considera que el
/// proceso estuvo congelado.
const STALL_GAP: u64 = 30;
/// Tope de bytes de un lote de shares (el mensaje máximo es 4 MiB).
const SHARE_BATCH_BYTES: usize = 1024 * 1024;
const BUCKET_CAP: u32 = 300;
const BUCKET_REFILL_PER_SEC: u64 = 30;
const MAX_INFLIGHT_TXS: usize = 100;
const MAX_KNOWN: usize = 4_000;
const MAX_REJECTS: usize = 5_000;
const ADDR_REPLY: usize = 50;
/// Shares esperando validación (de todos los pares).
const MAX_SHARE_QUEUE: usize = 512;
/// Caducidad de los shares huérfanos (segundos). El tope de retenidos depende de la ventana: para
/// unirse a una sharechain en marcha hay que retener toda la rama que se pide hacia atrás.
const SHARE_ORPHAN_TTL: u64 = 600;

type AddrKey = ([u8; 16], u16);
fn key(a: &NetAddr) -> AddrKey {
    (a.ip, a.port)
}

struct Peer {
    addr: NetAddr,
    inbound: bool,
    connected_at: u64,
    last_recv: u64,
    sent_version: bool,
    version: Option<Version>,
    got_verack: bool,
    ready: bool,
    score: u32,
    tokens: u32,
    last_refill: u64,
    ping: Option<(u64, u64)>,
    last_ping_at: u64,
    asked_addr: bool,
    got_addr: bool,
    served_addr: bool,
    /// Ids que el par ya conoce (por anuncio suyo o nuestro): no se le reenvían.
    known: HashSet<Hash32>,
    inflight_blocks: HashMap<Hash32, u64>,
    inflight_txs: HashSet<Hash32>,
    queue: VecDeque<Hash32>,
    awaiting_headers_since: Option<u64>,
    last_hdr: Option<(Hash32, bool)>,
    /// `GetShareChain` en vuelo: (share pedido, desde cuándo). Una petición por par.
    awaiting_shares: Option<(Hash32, u64)>,
}

impl Peer {
    fn new(addr: NetAddr, inbound: bool, now: u64) -> Peer {
        Peer {
            addr,
            inbound,
            connected_at: now,
            last_recv: now,
            sent_version: false,
            version: None,
            got_verack: false,
            ready: false,
            score: 0,
            tokens: BUCKET_CAP,
            last_refill: now,
            ping: None,
            last_ping_at: now,
            asked_addr: false,
            got_addr: false,
            served_addr: false,
            known: HashSet::new(),
            inflight_blocks: HashMap::new(),
            inflight_txs: HashSet::new(),
            queue: VecDeque::new(),
            awaiting_headers_since: None,
            last_hdr: None,
            awaiting_shares: None,
        }
    }
    fn wants_shares(&self) -> bool {
        self.version.as_ref().map_or(false, |v| v.services & SERVICE_SHARES != 0)
    }
    fn mark_known(&mut self, id: Hash32) {
        if self.known.len() >= MAX_KNOWN {
            self.known.clear();
        }
        self.known.insert(id);
    }
}

/// Verificador de PoW que no repite el trabajo ya hecho al validar cabeceras sueltas.
struct TrustedPow {
    inner: Box<dyn FullPow + Send>,
    /// Ids de cabeceras cuyo PoW verificamos nosotros (con su semilla de época real).
    trusted: HashSet<Hash32>,
}

const MAX_TRUSTED: usize = 20_000;

/// IP legible (IPv4 mapeada como a.b.c.d; otra, en hex).
fn fmt_ip(ip: &[u8; 16]) -> String {
    if ip[..10] == [0u8; 10] && ip[10] == 0xff && ip[11] == 0xff {
        format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15])
    } else {
        ip.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Vistas del mismo verificador como `PowCheck` (bloques) y como `SharePowCheck` (shares).
struct BlockPowRef<'a>(&'a mut (dyn FullPow + Send));
impl PowCheck for BlockPowRef<'_> {
    fn check(&mut self, h: &BlockHeader, seed: &[u8; 32]) -> Result<(), HeaderError> {
        PowCheck::check(&mut *self.0, h, seed)
    }
}
struct SharePowRef<'a>(&'a mut (dyn FullPow + Send));
impl SharePowCheck for SharePowRef<'_> {
    fn check_at(&mut self, h: &BlockHeader, seed: &[u8; 32], target: &U256) -> Result<[u8; 32], HeaderError> {
        SharePowCheck::check_at(&mut *self.0, h, seed, target)
    }
}

/// Share que no pudo validarse todavía porque falta su anterior (`block = false`) o su bloque padre.
struct ShareOrphan {
    share: Share,
    peer: PeerId,
    since: u64,
    block: bool,
}

impl PowCheck for TrustedPow {
    fn check(&mut self, header: &BlockHeader, epoch_seed: &[u8; 32]) -> Result<(), HeaderError> {
        // misma cabecera ⇒ mismos ancestros ⇒ misma semilla: el resultado ya se conoce
        if self.trusted.remove(&header.id()) {
            return Ok(());
        }
        self.inner.check(header, epoch_seed)
    }
}

/// Cabeceras de un par pendientes de validar (la validación se reparte en pasos).
struct HeaderSync {
    peer: PeerId,
    validator: HeaderValidator,
    pending: VecDeque<BlockHeader>,
    /// El lote llegó lleno: puede haber más después.
    full: bool,
}

pub struct Node {
    ledger: Ledger,
    pool: Mempool,
    store: Option<Store>,
    pow: TrustedPow,
    hsync: Option<HeaderSync>,
    shares: Option<ShareChain>,
    /// `shares.db`: los shares aceptados se añaden al archivo (si se pudo abrir).
    share_store: Option<ShareStore>,
    share_queue: VecDeque<(PeerId, Share)>,
    share_orphans: Vec<ShareOrphan>,
    /// Ids que ya pedimos por ser lo que falta a un huérfano (evita repetir la petición).
    orphan_asked: HashSet<Hash32>,
    /// Shares que deben admitirse como base de una sharechain vacía (ver `try_bootstrap`).
    base_ids: HashSet<Hash32>,
    events: Vec<String>,
    cfg: NodeConfig,
    nonce: u64,
    peers: BTreeMap<PeerId, Peer>,
    addrbook: BTreeMap<AddrKey, NetAddr>,
    failed: HashMap<AddrKey, u64>,
    bans: HashMap<[u8; 16], u64>,
    connecting: HashSet<AddrKey>,
    sync_peer: Option<PeerId>,
    rejected_txs: HashSet<Hash32>,
    ping_counter: u64,
    out: Vec<Action>,
    now: u64,
    /// Instante del evento anterior: si pasa mucho tiempo entre dos eventos, este proceso estuvo
    /// congelado (pantalla apagada en Android, suspensión) y los plazos de los pares no valen.
    last_event: u64,
    /// Error irrecuperable (p. ej. fallo de disco): el nodo deja de aceptar bloques nuevos.
    pub fatal: Option<String>,
}

impl Node {
    pub fn new(
        ledger: Ledger,
        pool: Mempool,
        store: Option<Store>,
        pow: Box<dyn FullPow + Send>,
        cfg: NodeConfig,
        nonce: u64,
    ) -> Node {
        let mut addrbook = BTreeMap::new();
        for s in &cfg.seeds {
            addrbook.insert(key(s), *s);
        }
        Node {
            ledger,
            pool,
            store,
            pow: TrustedPow { inner: pow, trusted: HashSet::new() },
            hsync: None,
            shares: None,
            share_store: None,
            share_queue: VecDeque::new(),
            share_orphans: vec![],
            orphan_asked: HashSet::new(),
            base_ids: HashSet::new(),
            events: Vec::new(),
            cfg,
            nonce,
            peers: BTreeMap::new(),
            addrbook,
            failed: HashMap::new(),
            bans: HashMap::new(),
            connecting: HashSet::new(),
            sync_peer: None,
            rejected_txs: HashSet::new(),
            ping_counter: 0,
            out: vec![],
            now: 0,
            last_event: 0,
            fatal: None,
        }
    }

    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }
    pub fn ledger_mut(&mut self) -> &mut Ledger {
        &mut self.ledger
    }
    pub fn pool(&self) -> &Mempool {
        &self.pool
    }
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
    pub fn ready_peer_count(&self) -> usize {
        self.peers.values().filter(|p| p.ready).count()
    }
    pub fn is_syncing(&self) -> bool {
        self.sync_peer.is_some()
    }
    pub fn known_addresses(&self) -> usize {
        self.addrbook.len()
    }
    /// Activa la sharechain (P2Pool). Debe hacerse antes de conectar con nadie: el saludo anuncia
    /// `SERVICE_SHARES`.
    pub fn enable_sharechain(&mut self, params: ShareParams) {
        if self.shares.is_none() {
            self.shares = Some(ShareChain::new(params));
        }
    }
    /// Abre `shares.db`, carga en la sharechain lo que guarda (los bloques ya deben estar cargados)
    /// y a partir de ahora anota cada share aceptado. Con `trust` no se re-ejecuta la VM (como
    /// `--trust-store`). Requiere `enable_sharechain`.
    pub fn enable_share_store(&mut self, path: &std::path::Path, trust: bool, now: u64) -> Result<ShareLoadReport, String> {
        let Some(sc) = self.shares.as_mut() else {
            return Err("la sharechain no está activa".into());
        };
        let chain = self.ledger.chain();
        let opened = if trust {
            ShareStore::open(path, chain, sc, now, &mut armax_chain::SkipPow)
        } else {
            ShareStore::open(path, chain, sc, now, &mut SharePowRef(self.pow.inner.as_mut()))
        };
        let (store, report) = opened.map_err(|e| format!("{}: {e}", path.display()))?;
        self.share_store = Some(store);
        Ok(report)
    }
    pub fn sharechain(&self) -> Option<&ShareChain> {
        self.shares.as_ref()
    }
    /// Shares retenidos por falta de su anterior o de su bloque padre.
    pub fn share_orphan_count(&self) -> usize {
        self.share_orphans.len()
    }
    /// Shares pendientes de validar.
    pub fn share_queue_len(&self) -> usize {
        self.share_queue.len()
    }
    pub fn is_banned(&self, ip: &[u8; 16]) -> bool {
        self.bans.get(ip).map_or(false, |&until| until > self.now)
    }

    // ---------------------------------------------------------------- API local

    /// Transacción creada localmente (cartera): al mempool y a la red.
    pub fn submit_tx(&mut self, now: u64, tx: Transaction) -> (Result<AddResult, MempoolError>, Vec<Action>) {
        self.now = now;
        let txid = tx.txid();
        let r = self.pool.add(tx, &self.ledger);
        if matches!(r, Ok(AddResult::Added) | Ok(AddResult::AddedDisplacing(_))) {
            self.announce_tx(txid, None);
        }
        (r, std::mem::take(&mut self.out))
    }

    /// Bloque minado localmente: se valida igual que uno ajeno y se anuncia.
    pub fn submit_block(&mut self, now: u64, fb: FullBlock) -> (Result<AddOutcome, LedgerError>, Vec<Action>) {
        self.now = now;
        let before = self.ledger.tip_id();
        let r = self.add_block_inner(fb, now).map_err(|e| match e {
            StoreError::Ledger(l) => l,
            other => LedgerError::Internal(match other {
                StoreError::Io(_) => "error de disco",
                _ => "error de almacenamiento",
            }),
        });
        if r.is_ok() {
            self.after_block(before, None);
        }
        (r, std::mem::take(&mut self.out))
    }

    /// Share hallado localmente: se valida igual que uno ajeno, se retransmite y, si además cumple
    /// el target del bloque, se publica como bloque. `Err(BadExtra)` si la sharechain no está activa.
    pub fn submit_share(&mut self, now: u64, share: Share) -> (Result<AddShare, ShareError>, Vec<Action>) {
        self.now = now;
        let r = if self.shares.is_some() { self.process_share(None, share) } else { Err(ShareError::BadExtra) };
        (r, std::mem::take(&mut self.out))
    }

    // ---------------------------------------------------------------- eventos

    pub fn handle(&mut self, now: u64, ev: Event) -> Vec<Action> {
        self.now = now;
        if self.last_event != 0 && now > self.last_event + STALL_GAP {
            self.rebase_timers(now);
        }
        self.last_event = now;
        match ev {
            Event::Connected { peer, addr, inbound } => self.on_connected(peer, addr, inbound),
            Event::ConnectFailed(addr) => {
                self.connecting.remove(&key(&addr));
                self.failed.insert(key(&addr), now + self.cfg.connect_backoff);
            }
            Event::Disconnected(peer) => {
                if self.peers.contains_key(&peer) {
                    let l = self.peer_label(peer);
                    self.log(format!("conexión con {l} cerrada (por el par o por la red)"));
                }
                self.drop_peer(peer)
            }
            Event::Message(peer, msg) => self.on_message(peer, msg),
            Event::Tick => self.on_tick(),
        }
        std::mem::take(&mut self.out)
    }

    fn send(&mut self, peer: PeerId, m: Message) {
        self.out.push(Action::Send(peer, m));
    }

    /// Mensajes para el operador (desconexiones, castigos): el bucle de E/S los imprime.
    fn log(&mut self, s: String) {
        if self.events.len() < 200 {
            self.events.push(s);
        }
    }

    pub fn take_events(&mut self) -> Vec<String> {
        std::mem::take(&mut self.events)
    }

    fn peer_label(&self, peer: PeerId) -> String {
        self.peers.get(&peer).map_or(format!("#{peer}"), |p| fmt_ip(&p.addr.ip))
    }

    #[track_caller]
    fn disconnect(&mut self, peer: PeerId) {
        if self.peers.contains_key(&peer) {
            let (l, loc) = (self.peer_label(peer), std::panic::Location::caller());
            self.log(format!("desconecto a {l} (node.rs:{})", loc.line()));
            self.out.push(Action::Disconnect(peer));
            self.drop_peer(peer);
        }
    }

    fn drop_peer(&mut self, peer: PeerId) {
        self.peers.remove(&peer);
        if self.sync_peer == Some(peer) {
            self.sync_peer = None;
        }
        if self.hsync.as_ref().map_or(false, |h| h.peer == peer) {
            self.hsync = None;
        }
        self.share_queue.retain(|(p, _)| *p != peer);
    }

    #[track_caller]
    fn misbehave(&mut self, peer: PeerId, points: u32) {
        let loc = std::panic::Location::caller();
        let Some(p) = self.peers.get_mut(&peer) else { return };
        p.score += points;
        let (l, score) = (fmt_ip(&p.addr.ip), p.score);
        self.log(format!("castigo +{points} a {l} (total {score}, node.rs:{})", loc.line()));
        let Some(p) = self.peers.get_mut(&peer) else { return };
        if p.score >= self.cfg.ban_threshold {
            let ip = p.addr.ip;
            self.bans.insert(ip, self.now + self.cfg.ban_seconds);
            // se desconectan también otros pares de la misma IP
            let same: Vec<PeerId> = self.peers.iter().filter(|(_, q)| q.addr.ip == ip).map(|(id, _)| *id).collect();
            for id in same {
                self.disconnect(id);
            }
        }
    }

    fn on_connected(&mut self, peer: PeerId, addr: NetAddr, inbound: bool) {
        self.connecting.remove(&key(&addr));
        let inbound_count = self.peers.values().filter(|p| p.inbound).count();
        if self.is_banned(&addr.ip) || (inbound && (!self.cfg.serve || inbound_count >= self.cfg.max_inbound)) {
            self.out.push(Action::Disconnect(peer));
            return;
        }
        self.peers.insert(peer, Peer::new(addr, inbound, self.now));
        let v = Version {
            protocol: PROTOCOL_VERSION,
            services: (if self.cfg.serve { SERVICE_SERVE } else { 0 })
                | (if self.shares.is_some() { SERVICE_SHARES } else { 0 }),
            genesis: self.ledger.chain().genesis_id(),
            tip: self.ledger.tip_id(),
            tip_height: self.ledger.tip_height(),
            tip_work: self.ledger.chain().tip_work(),
            nonce: self.nonce,
            listen_port: if self.cfg.serve { self.cfg.listen_port } else { 0 },
        };
        self.peers.get_mut(&peer).unwrap().sent_version = true;
        self.send(peer, Message::Version(v));
    }

    fn on_message(&mut self, peer: PeerId, msg: Message) {
        let now = self.now;
        let Some(p) = self.peers.get_mut(&peer) else { return };
        p.last_recv = now;
        // cubo de fichas
        let refill = (now.saturating_sub(p.last_refill) * BUCKET_REFILL_PER_SEC).min(BUCKET_CAP as u64) as u32;
        if refill > 0 {
            p.tokens = (p.tokens + refill).min(BUCKET_CAP);
            p.last_refill = now;
        }
        // un bloque pedido cuesta lo mismo que cualquier mensaje (ya está acotado por las peticiones
        // en vuelo); uno no pedido es caro: es la forma de empujarnos trabajo
        // Las respuestas que esperábamos (bloques pedidos, lista de ids) no gastan fichas: la
        // descarga inicial puede ser muy rápida y ya está acotada por lo que pedimos.
        let cost = match &msg {
            Message::Block(fb) if p.inflight_blocks.contains_key(&fb.id()) => 0,
            Message::Block(_) => 10,
            Message::Headers(_) if p.awaiting_headers_since.is_some() => 0,
            Message::Shares(_) if p.awaiting_shares.is_some() => 0,
            _ => 1,
        };
        if p.tokens < cost {
            self.disconnect(peer);
            return;
        }
        p.tokens -= cost;

        let ready = p.ready;
        match msg {
            Message::Version(v) => self.on_version(peer, v),
            Message::Verack => self.on_verack(peer),
            _ if !ready => {
                // cualquier otra cosa antes de terminar el saludo
                self.misbehave(peer, 50);
                self.disconnect(peer);
            }
            Message::Ping(n) => self.send(peer, Message::Pong(n)),
            Message::Pong(n) => {
                let p = self.peers.get_mut(&peer).unwrap();
                match p.ping {
                    Some((expected, _)) if expected == n => p.ping = None,
                    _ => self.misbehave(peer, 10),
                }
            }
            Message::GetAddr => self.on_getaddr(peer),
            Message::Addr(list) => self.on_addr(peer, list),
            Message::GetHeaders { locator } => self.on_getheaders(peer, locator),
            Message::Headers(hs) => self.on_headers(peer, hs),
            Message::GetBlocks(ids) => self.on_getblocks(peer, ids),
            Message::NotFound(ids) => {
                let p = self.peers.get_mut(&peer).unwrap();
                for id in &ids {
                    p.inflight_blocks.remove(id);
                }
            }
            Message::Block(fb) => self.on_block(peer, *fb),
            Message::InvBlocks(ids) => self.on_inv_blocks(peer, ids),
            Message::InvTxs(ids) => self.on_inv_txs(peer, ids),
            Message::GetTxs(ids) => {
                for id in ids.iter().take(MAX_IDS) {
                    if let Some(tx) = self.pool.get(id) {
                        let m = Message::Tx(Box::new(tx.clone()));
                        self.send(peer, m);
                    }
                }
            }
            Message::Tx(tx) => self.on_tx(peer, *tx),
            Message::InvShares(ids) => self.on_inv_shares(peer, ids),
            Message::GetShareChain { from, max } => self.on_get_share_chain(peer, from, max),
            Message::Shares(list) => self.on_shares(peer, list),
        }
        if self.peers.contains_key(&peer) {
            self.pump(peer);
        }
        self.step_shares();
    }

    // ---------------------------------------------------------------- saludo

    fn on_version(&mut self, peer: PeerId, v: Version) {
        if self.peers[&peer].version.is_some() {
            self.misbehave(peer, 20);
            return;
        }
        if v.protocol != PROTOCOL_VERSION || v.genesis != self.ledger.chain().genesis_id() || v.nonce == self.nonce {
            // otra red, otra versión, o somos nosotros mismos
            if v.nonce != self.nonce {
                self.misbehave(peer, self.cfg.ban_threshold);
            }
            self.disconnect(peer);
            return;
        }
        self.peers.get_mut(&peer).unwrap().version = Some(v);
        self.send(peer, Message::Verack);
        self.check_ready(peer);
    }

    fn on_verack(&mut self, peer: PeerId) {
        let p = self.peers.get_mut(&peer).unwrap();
        if p.got_verack || !p.sent_version {
            self.misbehave(peer, 20);
            return;
        }
        p.got_verack = true;
        self.check_ready(peer);
    }

    fn check_ready(&mut self, peer: PeerId) {
        let p = self.peers.get_mut(&peer).unwrap();
        if p.ready || p.version.is_none() || !p.got_verack {
            return;
        }
        p.ready = true;
        p.last_ping_at = self.now;
        let (inbound, addr) = (p.inbound, p.addr);
        // un par saliente al que marcamos es alcanzable por definición
        if !inbound {
            let mut a = addr;
            a.last_seen = self.now;
            a.services = SERVICE_SERVE;
            self.add_addr(a);
            self.peers.get_mut(&peer).unwrap().asked_addr = true;
            self.send(peer, Message::GetAddr);
        }
        if self.cfg.serve {
            if let Some(mut me) = self.cfg.external_addr {
                me.last_seen = self.now;
                self.send(peer, Message::Addr(vec![me]));
            }
        }
        // punta de la sharechain, si ambos participamos
        let share_tip = self.shares.as_ref().and_then(|sc| sc.tip());
        if let Some(t) = share_tip {
            let p = self.peers.get_mut(&peer).unwrap();
            if p.wants_shares() {
                p.mark_known(t);
                self.send(peer, Message::InvShares(vec![t]));
            }
        }
        // mempool actual
        let ids: Vec<Hash32> = self.pool.candidates().iter().take(MAX_IDS).map(|t| t.txid()).collect();
        if !ids.is_empty() {
            let p = self.peers.get_mut(&peer).unwrap();
            for id in &ids {
                p.mark_known(*id);
            }
            self.send(peer, Message::InvTxs(ids));
        }
        self.maybe_sync();
    }

    // ---------------------------------------------------------------- direcciones

    /// `true` si la dirección era nueva en la libreta.
    fn add_addr(&mut self, a: NetAddr) -> bool {
        if a.port == 0 || a.is_unspecified_or_multicast() || a.services & SERVICE_SERVE == 0 {
            return false;
        }
        if Some(key(&a)) == self.cfg.external_addr.as_ref().map(key) {
            return false;
        }
        let mut a = a;
        a.last_seen = a.last_seen.min(self.now);
        match self.addrbook.get_mut(&key(&a)) {
            Some(old) => {
                old.last_seen = old.last_seen.max(a.last_seen);
                false
            }
            None => {
                if self.addrbook.len() >= self.cfg.max_addrbook {
                    // se descarta la menos reciente
                    let oldest = self.addrbook.iter().min_by_key(|(k, v)| (v.last_seen, **k)).map(|(k, _)| *k);
                    if let Some(k) = oldest {
                        self.addrbook.remove(&k);
                    }
                }
                self.addrbook.insert(key(&a), a);
                true
            }
        }
    }

    fn on_getaddr(&mut self, peer: PeerId) {
        let p = self.peers.get_mut(&peer).unwrap();
        if p.served_addr {
            return;
        }
        p.served_addr = true;
        let mut list: Vec<NetAddr> = self.addrbook.values().copied().collect();
        list.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then(key(a).cmp(&key(b))));
        list.truncate(ADDR_REPLY);
        self.send(peer, Message::Addr(list));
    }

    fn on_addr(&mut self, peer: PeerId, list: Vec<NetAddr>) {
        let p = self.peers.get_mut(&peer).unwrap();
        // se acepta la respuesta a nuestro GetAddr y los anuncios de la propia dirección (1 entrada)
        if p.asked_addr && !p.got_addr {
            p.got_addr = true;
        } else if list.len() > 1 {
            self.misbehave(peer, 20);
            return;
        }
        let single = list.len() == 1;
        for a in list {
            // un anuncio nuevo de una sola dirección se reenvía a un par de vecinos (gossip acotado)
            if self.add_addr(a) && single && self.now.saturating_sub(a.last_seen) < 600 {
                let mut a = a;
                a.last_seen = a.last_seen.min(self.now);
                let targets: Vec<PeerId> = self
                    .peers
                    .iter()
                    .filter(|(id, q)| **id != peer && q.ready && q.addr.ip != a.ip)
                    .map(|(id, _)| *id)
                    .take(2)
                    .collect();
                for t in targets {
                    self.send(t, Message::Addr(vec![a]));
                }
            }
        }
    }

    // ---------------------------------------------------------------- sincronización

    fn locator(&self, first: Option<Hash32>) -> Vec<Hash32> {
        let main = self.ledger.chain().main_ids(); // génesis → punta
        let mut loc = Vec::new();
        if let Some(f) = first {
            loc.push(f);
        }
        let (mut step, mut i) = (1usize, main.len() as i64 - 1);
        while i > 0 && loc.len() < MAX_LOCATOR - 1 {
            loc.push(main[i as usize]);
            if loc.len() >= 10 {
                step *= 2;
            }
            i -= step as i64;
        }
        loc.push(main[0]);
        loc.truncate(MAX_LOCATOR);
        loc
    }

    fn on_getheaders(&mut self, peer: PeerId, locator: Vec<Hash32>) {
        let chain = self.ledger.chain();
        let start = locator.iter().find_map(|id| chain.main_height_of(id)).unwrap_or(0) as usize;
        let hs: Vec<BlockHeader> =
            chain.main_ids().iter().skip(start + 1).take(MAX_HEADERS).filter_map(|id| chain.header(id).cloned()).collect();
        self.send(peer, Message::Headers(hs));
    }

    /// Elige un par con más trabajo que el nuestro y empieza a sincronizar con él.
    fn maybe_sync(&mut self) {
        if self.sync_peer.is_some() {
            return;
        }
        let ours = self.ledger.chain().tip_work();
        let best = self
            .peers
            .iter()
            .filter(|(_, p)| p.ready && p.awaiting_headers_since.is_none())
            .filter_map(|(id, p)| p.version.as_ref().map(|v| (*id, v.tip_work)))
            .filter(|(_, w)| *w > ours)
            .max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0)));
        if let Some((id, _)) = best {
            self.start_sync(id);
        }
    }

    /// Termina la sincronización con `peer`. Su trabajo declarado en el saludo ya no cuenta como
    /// "más que el nuestro" (si mentía, no lo reintentamos en cada tick; si mina más, nos lo anuncia).
    fn finish_sync(&mut self, peer: PeerId) {
        let ours = self.ledger.chain().tip_work();
        if let Some(v) = self.peers.get_mut(&peer).and_then(|p| p.version.as_mut()) {
            if v.tip_work > ours {
                v.tip_work = ours;
            }
        }
        if self.sync_peer == Some(peer) {
            self.sync_peer = None;
        }
        self.maybe_sync();
    }

    fn start_sync(&mut self, peer: PeerId) {
        if self.sync_peer.is_some() && self.sync_peer != Some(peer) {
            return;
        }
        self.sync_peer = Some(peer);
        self.hsync = None;
        let loc = self.locator(None);
        let now = self.now;
        let p = self.peers.get_mut(&peer).unwrap();
        p.awaiting_headers_since = Some(now);
        p.queue.clear();
        p.last_hdr = None;
        self.send(peer, Message::GetHeaders { locator: loc });
    }

    fn on_headers(&mut self, peer: PeerId, hs: Vec<BlockHeader>) {
        let p = self.peers.get_mut(&peer).unwrap();
        if p.awaiting_headers_since.take().is_none() || self.sync_peer != Some(peer) {
            self.misbehave(peer, 20);
            return;
        }
        if hs.is_empty() {
            self.finish_sync(peer);
            return;
        }
        self.hsync = Some(HeaderSync {
            peer,
            validator: HeaderValidator::new(),
            full: hs.len() == MAX_HEADERS,
            pending: hs.into(),
        });
        self.step_headers();
    }

    /// Valida hasta `headers_per_step` cabeceras pendientes del par con el que sincronizamos.
    /// Al terminar el lote pasa a pedir los cuerpos. Se llama tras recibir cabeceras y en cada tick.
    fn step_headers(&mut self) {
        let Some(mut hs) = self.hsync.take() else { return };
        let peer = hs.peer;
        if !self.peers.contains_key(&peer) || self.sync_peer != Some(peer) {
            return;
        }
        let now = self.now;
        for _ in 0..self.cfg.headers_per_step.max(1) {
            let Some(h) = hs.pending.pop_front() else { break };
            let before = hs.validator.len();
            // el PoW se ejecuta en `inner`: la lista de confiados solo sirve para no repetirlo después
            match hs.validator.push(self.ledger.chain(), &h, now, &mut BlockPowRef(self.pow.inner.as_mut())) {
                Ok(()) => {
                    if hs.validator.len() > before {
                        if self.pow.trusted.len() >= MAX_TRUSTED {
                            self.pow.trusted.clear();
                        }
                        self.pow.trusted.insert(h.id());
                    }
                }
                Err(e) => {
                    self.headers_failed(peer, e);
                    return;
                }
            }
        }
        if hs.pending.is_empty() {
            self.headers_done(hs);
        } else {
            self.hsync = Some(hs);
        }
    }

    fn headers_failed(&mut self, peer: PeerId, e: ChainError) {
        match e {
            // reloj desfasado (el nuestro o el suyo): no se castiga
            ChainError::Header(HeaderError::TimestampTooFarInFuture { .. }) => {}
            // no engancha con nuestra cadena: puede ser una carrera legítima, castigo leve
            ChainError::UnknownParent => self.misbehave(peer, 20),
            // PoW falso, target o enlace incorrectos, rama inválida: como un bloque inválido
            _ => self.misbehave(peer, self.cfg.ban_threshold),
        }
        self.finish_sync(peer);
    }

    /// Lote de cabeceras validado: se encolan los cuerpos que faltan.
    fn headers_done(&mut self, hs: HeaderSync) {
        let peer = hs.peer;
        let new_ids = hs.validator.new_ids().to_vec();
        let others: HashSet<Hash32> = self.peers.values().flat_map(|q| q.inflight_blocks.keys().copied()).collect();
        let want: Vec<Hash32> =
            new_ids.iter().filter(|id| !self.ledger.chain().contains(*id) && !others.contains(*id)).copied().collect();
        let p = self.peers.get_mut(&peer).unwrap();
        p.last_hdr = new_ids.last().map(|l| (*l, hs.full));
        p.queue.extend(want);
        self.pump(peer);
    }

    /// Pide los bloques que faltan (hasta el límite en vuelo) y, al terminar un tramo, el siguiente.
    fn pump(&mut self, peer: PeerId) {
        if self.sync_peer != Some(peer) {
            return;
        }
        let now = self.now;
        let max = self.cfg.max_inflight_blocks;
        let validating = self.hsync.is_some();
        let p = self.peers.get_mut(&peer).unwrap();
        let mut batch: Vec<Hash32> = vec![];
        // se rellena cuando queda la mitad en vuelo: peticiones en lotes, no de una en una
        let refill = p.inflight_blocks.len() <= max / 2;
        while refill && p.inflight_blocks.len() + batch.len() < max && batch.len() < MAX_GETBLOCKS {
            match p.queue.pop_front() {
                Some(id) => batch.push(id),
                None => break,
            }
        }
        for id in &batch {
            p.inflight_blocks.insert(*id, now);
        }
        let idle = p.queue.is_empty()
            && p.inflight_blocks.is_empty()
            && p.awaiting_headers_since.is_none()
            && !validating;
        let last = p.last_hdr;
        if !batch.is_empty() {
            self.send(peer, Message::GetBlocks(batch));
            return;
        }
        if idle {
            match last {
                Some((last_id, true)) => {
                    let loc = self.locator(Some(last_id));
                    let p = self.peers.get_mut(&peer).unwrap();
                    p.awaiting_headers_since = Some(now);
                    p.last_hdr = None;
                    self.send(peer, Message::GetHeaders { locator: loc });
                }
                _ => {
                    // tramo corto o vacío: ya estamos al día con este par
                    self.finish_sync(peer);
                }
            }
        }
    }

    fn on_getblocks(&mut self, peer: PeerId, ids: Vec<Hash32>) {
        let mut missing = vec![];
        for id in ids {
            match self.ledger.full_block(&id) {
                Some(fb) => self.send(peer, Message::Block(Box::new(fb))),
                None => missing.push(id),
            }
        }
        if !missing.is_empty() {
            self.send(peer, Message::NotFound(missing));
        }
    }

    fn on_inv_blocks(&mut self, peer: PeerId, ids: Vec<Hash32>) {
        let now = self.now;
        let others: HashSet<Hash32> = self.peers.values().flat_map(|q| q.inflight_blocks.keys().copied()).collect();
        let mut ask = vec![];
        {
            let p = self.peers.get_mut(&peer).unwrap();
            for id in ids {
                p.mark_known(id);
                if !self.ledger.chain().contains(&id)
                    && !others.contains(&id)
                    && p.inflight_blocks.len() + ask.len() < MAX_GETBLOCKS
                {
                    ask.push(id);
                }
            }
            for id in &ask {
                p.inflight_blocks.insert(*id, now);
            }
        }
        if !ask.is_empty() {
            self.send(peer, Message::GetBlocks(ask));
        }
    }

    fn add_block_inner(&mut self, fb: FullBlock, now: u64) -> Result<AddOutcome, StoreError> {
        match self.store.as_mut() {
            Some(st) => st.add_block(&mut self.ledger, fb, now, &mut self.pow),
            None => self.ledger.add_block(fb, now, &mut self.pow).map_err(StoreError::Ledger),
        }
    }

    fn on_block(&mut self, peer: PeerId, fb: FullBlock) {
        let id = fb.id();
        let requested = self.peers.get_mut(&peer).unwrap().inflight_blocks.remove(&id).is_some();
        if !requested {
            self.misbehave(peer, 20);
            return;
        }
        if self.fatal.is_some() {
            return;
        }
        self.peers.get_mut(&peer).unwrap().mark_known(id);
        let before = self.ledger.tip_id();
        match self.add_block_inner(fb, self.now) {
            Ok(_) => self.after_block(before, Some(peer)),
            Err(StoreError::Ledger(LedgerError::Chain(ChainError::UnknownParent)))
            | Err(StoreError::Ledger(LedgerError::Chain(ChainError::Header(HeaderError::NoParent)))) => {
                // un anuncio cuyo padre no tenemos: nos faltan bloques, sincronizar con este par
                if self.sync_peer == Some(peer) {
                    self.misbehave(peer, 20);
                } else {
                    self.start_sync(peer);
                }
            }
            Err(StoreError::Ledger(LedgerError::Chain(ChainError::Header(HeaderError::TimestampTooFarInFuture {
                ..
            })))) => {
                // puede ser un reloj desfasado (el nuestro o el suyo): no se castiga
            }
            Err(StoreError::Ledger(LedgerError::Chain(ChainError::InvalidParent))) => self.misbehave(peer, 50),
            Err(StoreError::Ledger(LedgerError::ReorgTooDeep { .. })) => {
                // su rama tiene más trabajo pero exige deshacer más de lo que conservamos: no es un bloque inválido
                // ni un ataque evidente, así que no se castiga; la rama queda descartada
            }
            Err(StoreError::Ledger(_)) => self.misbehave(peer, self.cfg.ban_threshold),
            Err(e) => self.fatal = Some(format!("{e}")),
        }
    }

    /// Tras aceptar un bloque: mempool al día y anuncio de la nueva punta.
    fn after_block(&mut self, tip_before: Hash32, source: Option<PeerId>) {
        self.pool.on_chain_update(&mut self.ledger);
        self.requeue_block_orphans();
        let tip = self.ledger.tip_id();
        // durante la descarga inicial no se anuncia cada bloque: los demás ya lo tienen o lo recibirán de otros
        if tip != tip_before && (source.is_none() || self.sync_peer.is_none()) {
            let ids = [tip].to_vec();
            let targets: Vec<PeerId> =
                self.peers.iter().filter(|(id, p)| p.ready && Some(**id) != source && !p.known.contains(&tip)).map(|(id, _)| *id).collect();
            for t in targets {
                self.peers.get_mut(&t).unwrap().mark_known(tip);
                self.send(t, Message::InvBlocks(ids.clone()));
            }
        }
    }

    // ---------------------------------------------------------------- transacciones

    fn announce_tx(&mut self, txid: Hash32, source: Option<PeerId>) {
        let targets: Vec<PeerId> =
            self.peers.iter().filter(|(id, p)| p.ready && Some(**id) != source && !p.known.contains(&txid)).map(|(id, _)| *id).collect();
        for t in targets {
            self.peers.get_mut(&t).unwrap().mark_known(txid);
            self.send(t, Message::InvTxs(vec![txid]));
        }
    }

    fn on_inv_txs(&mut self, peer: PeerId, ids: Vec<Hash32>) {
        let mut ask = vec![];
        {
            let p = self.peers.get_mut(&peer).unwrap();
            for id in ids {
                p.mark_known(id);
                if !self.pool.contains(&id)
                    && !self.rejected_txs.contains(&id)
                    && !p.inflight_txs.contains(&id)
                    && p.inflight_txs.len() + ask.len() < MAX_INFLIGHT_TXS
                {
                    ask.push(id);
                }
            }
            for id in &ask {
                p.inflight_txs.insert(*id);
            }
        }
        if !ask.is_empty() {
            self.send(peer, Message::GetTxs(ask));
        }
    }

    fn on_tx(&mut self, peer: PeerId, tx: Transaction) {
        let txid = tx.txid();
        if !self.peers.get_mut(&peer).unwrap().inflight_txs.remove(&txid) {
            self.misbehave(peer, 10);
            return;
        }
        match self.pool.add(tx, &self.ledger) {
            Ok(AddResult::Added) | Ok(AddResult::AddedDisplacing(_)) => self.announce_tx(txid, Some(peer)),
            Ok(AddResult::AlreadyKnown) => {}
            Err(e) => {
                if self.rejected_txs.len() >= MAX_REJECTS {
                    self.rejected_txs.clear();
                }
                self.rejected_txs.insert(txid);
                match e {
                    MempoolError::Invalid(_) => self.misbehave(peer, self.cfg.ban_threshold),
                    MempoolError::BadShape | MempoolError::TooLarge(_) | MempoolError::DuplicateInput => {
                        self.misbehave(peer, 50)
                    }
                    // carreras normales con bloques nuevos, comisión baja, pool lleno…
                    _ => {}
                }
            }
        }
    }


    // ---------------------------------------------------------------- sharechain

    /// Un par anuncia shares: pedimos el primero que no tengamos (uno a la vez por par).
    fn on_inv_shares(&mut self, peer: PeerId, ids: Vec<Hash32>) {
        let Some(sc) = self.shares.as_ref() else {
            // no pedimos shares: este par no debería enviárnoslos
            self.misbehave(peer, 20);
            return;
        };
        let p = self.peers.get_mut(&peer).unwrap();
        let mut ask = None;
        for id in ids {
            p.mark_known(id);
            if ask.is_none() && !sc.contains(&id) {
                ask = Some(id);
            }
        }
        if let (Some(id), None) = (ask, p.awaiting_shares) {
            p.awaiting_shares = Some((id, self.now));
            self.send(peer, Message::GetShareChain { from: id, max: 1 });
        }
    }

    fn on_get_share_chain(&mut self, peer: PeerId, from: Hash32, max: u16) {
        let max = (max as usize).clamp(1, MAX_SHARES);
        // del más reciente hacia atrás, sin pasar de ~1 MiB (los shares con transacciones pesan más);
        // el lote sale del más antiguo al más reciente y termina siempre en `from`
        let mut list: Vec<Share> = vec![];
        if let Some(sc) = self.shares.as_ref() {
            let mut bytes = 0usize;
            for id in sc.ids_back(&from, max) {
                let Some(sh) = sc.get(&id) else { break };
                bytes += sh.to_bytes().len();
                if !list.is_empty() && bytes > SHARE_BATCH_BYTES {
                    break;
                }
                list.push(sh.clone());
            }
            list.reverse();
        }
        self.send(peer, Message::Shares(list));
    }

    /// Respuesta a nuestro `GetShareChain`: se encolan para validarlos por pasos.
    fn on_shares(&mut self, peer: PeerId, list: Vec<Share>) {
        let Some((from, _)) = self.peers.get_mut(&peer).unwrap().awaiting_shares.take() else {
            self.misbehave(peer, 20);
            return;
        };
        if self.shares.is_none() {
            return;
        }
        if list.is_empty() {
            // el par ya no tiene `from` (podó su historia): si estamos empezando de cero, los
            // huérfanos que cuelgan de él sirven de base
            self.try_bootstrap(from);
            return;
        }
        if list.last().map(|s| s.id()) != Some(from) {
            self.misbehave(peer, 20);
            return;
        }
        // el lote debe ser una cadena continua, del más antiguo al más reciente
        let linked = list.windows(2).all(|w| w[1].meta().map(|m| m.prev_share) == Some(w[0].id()));
        if !linked {
            self.misbehave(peer, 50);
            return;
        }
        for sh in list {
            if self.share_queue.len() >= MAX_SHARE_QUEUE {
                break;
            }
            self.share_queue.push_back((peer, sh));
        }
    }

    /// Valida hasta `shares_per_step` shares de la cola (cada uno cuesta una ejecución de la VM).
    fn step_shares(&mut self) {
        if self.shares.is_none() {
            return;
        }
        for _ in 0..self.cfg.shares_per_step.max(1) {
            let Some((peer, share)) = self.share_queue.pop_front() else { break };
            let keep = share.clone();
            let base = self.base_ids.contains(&share.id());
            match self.process_share_as(Some(peer), share, base) {
                Ok(_) => {
                    if base {
                        self.base_ids.clear();
                    }
                }
                Err(e) if e.is_orphan() => self.hold_orphan(peer, keep, matches!(e, ShareError::UnknownParent)),
                // reloj desfasado (el nuestro o el suyo): no se castiga
                Err(ShareError::Header(HeaderError::TimestampTooFarInFuture { .. })) => {}
                // con todo su contexto conocido el resultado es determinista: el share es inválido
                Err(_) => self.misbehave(peer, self.cfg.ban_threshold),
            }
        }
    }

    /// Valida e incorpora un share (de un par o propio) y, si procede, lo retransmite y lo publica
    /// como bloque. No castiga: eso lo decide quien llama.
    fn process_share(&mut self, source: Option<PeerId>, share: Share) -> Result<AddShare, ShareError> {
        self.process_share_as(source, share, false)
    }

    fn process_share_as(&mut self, source: Option<PeerId>, share: Share, base: bool) -> Result<AddShare, ShareError> {
        let id = share.id();
        let now = self.now;
        let res = {
            let sc = self.shares.as_mut().expect("sharechain activa");
            let pow = &mut SharePowRef(self.pow.inner.as_mut());
            if base {
                sc.add_base(share.clone(), self.ledger.chain(), now, pow)?
            } else {
                sc.add(share.clone(), self.ledger.chain(), now, pow)?
            }
        };
        let AddShare::Added { is_block, .. } = res else { return Ok(res) };
        // al disco (si falla, se sigue sin persistencia: la sharechain se recupera de la red)
        if let Some(st) = self.share_store.as_mut() {
            let mut failed = st.append(&share).err();
            if failed.is_none() && st.needs_compaction(self.shares.as_ref().map_or(0, |s| s.len())) {
                failed = self.shares.as_ref().and_then(|sc| st.compact(sc).err());
            }
            if let Some(e) = failed {
                self.share_store = None;
                self.log(format!("no se pudo escribir shares.db ({e}): sigo sin guardar shares"));
            }
        }
        // retransmisión a los pares que participan y no lo conocen
        let targets: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(pid, p)| p.ready && p.wants_shares() && Some(**pid) != source && !p.known.contains(&id))
            .map(|(pid, _)| *pid)
            .collect();
        for t in targets {
            self.peers.get_mut(&t).unwrap().mark_known(id);
            self.send(t, Message::InvShares(vec![id]));
        }
        // los huérfanos que colgaban de este share ya pueden validarse (van los primeros)
        let (ready, rest): (Vec<ShareOrphan>, Vec<ShareOrphan>) = std::mem::take(&mut self.share_orphans)
            .into_iter()
            .partition(|o| !o.block && o.share.meta().map(|m| m.prev_share) == Some(id));
        self.share_orphans = rest;
        for o in ready.into_iter().rev() {
            self.share_queue.push_front((o.peer, o.share));
        }
        if is_block {
            // el PoW completo ya está verificado (cumple el target del bloque): no se repite
            if self.pow.trusted.len() >= MAX_TRUSTED {
                self.pow.trusted.clear();
            }
            self.pow.trusted.insert(id);
            let before = self.ledger.tip_id();
            match self.add_block_inner(FullBlock { block: share.to_block(), txs: share.txs.clone() }, now) {
                Ok(_) => self.after_block(before, None),
                Err(StoreError::Ledger(_)) => {} // p. ej. ya lo teníamos
                Err(e) => self.fatal = Some(format!("{e}")),
            }
        }
        Ok(res)
    }

    /// Retiene un share al que le falta su anterior o su bloque padre y pide lo que falta.
    fn hold_orphan(&mut self, peer: PeerId, share: Share, block: bool) {
        let id = share.id();
        if self.share_orphans.iter().any(|o| o.share.id() == id) {
            return;
        }
        let cap = self.shares.as_ref().map_or(0, |sc| sc.params().window * 2 + 64);
        if self.share_orphans.len() >= cap {
            self.share_orphans.remove(0);
        }
        let missing = if block { Some(share.header.prev_hash) } else { share.meta().map(|m| m.prev_share) };
        self.share_orphans.push(ShareOrphan { share, peer, since: self.now, block });
        let Some(missing) = missing else { return };
        if !block && self.share_orphans.iter().any(|o| o.share.id() == missing) {
            return; // ya lo tenemos retenido: lo que falta está más atrás
        }
        if self.orphan_asked.len() >= 1_000 {
            self.orphan_asked.clear();
        }
        if self.orphan_asked.contains(&missing) {
            return;
        }
        let now = self.now;
        let others: HashSet<Hash32> = self.peers.values().flat_map(|q| q.inflight_blocks.keys().copied()).collect();
        let Some(p) = self.peers.get_mut(&peer) else { return };
        if block {
            if !self.ledger.chain().contains(&missing) && !others.contains(&missing) && p.inflight_blocks.len() < MAX_GETBLOCKS {
                p.inflight_blocks.insert(missing, now);
                self.orphan_asked.insert(missing);
                self.send(peer, Message::GetBlocks(vec![missing]));
            }
        } else if p.awaiting_shares.is_none() {
            p.awaiting_shares = Some((missing, now));
            self.orphan_asked.insert(missing);
            self.send(peer, Message::GetShareChain { from: missing, max: MAX_SHARES as u16 });
        }
    }

    /// Pide lo que falta a los huérfanos cuya petición no pudo salir en su momento (el par estaba
    /// ocupado con otra). Una por tick.
    fn retry_orphan_requests(&mut self) {
        if self.share_orphans.is_empty() {
            self.orphan_asked.clear();
            return;
        }
        let Some(sc) = self.shares.as_ref() else { return };
        let held: HashSet<Hash32> = self.share_orphans.iter().map(|o| o.share.id()).collect();
        let missing = self
            .share_orphans
            .iter()
            .filter(|o| !o.block)
            .filter_map(|o| o.share.meta())
            .map(|m| m.prev_share)
            .find(|p| !held.contains(p) && !sc.contains(p) && !self.orphan_asked.contains(p));
        let Some(m) = missing else { return };
        let now = self.now;
        let pid = self.peers.iter().find(|(_, p)| p.ready && p.wants_shares() && p.awaiting_shares.is_none()).map(|(i, _)| *i);
        if let Some(pid) = pid {
            self.peers.get_mut(&pid).unwrap().awaiting_shares = Some((m, now));
            self.orphan_asked.insert(m);
            self.send(pid, Message::GetShareChain { from: m, max: MAX_SHARES as u16 });
        }
    }

    /// El par no tiene el share `missing` (anterior de varios huérfanos): si nuestra sharechain
    /// está vacía, el huérfano que cuelga de él pasa a ser la base y el resto se encadena detrás.
    fn try_bootstrap(&mut self, missing: Hash32) {
        if !self.shares.as_ref().map_or(false, |sc| sc.is_empty()) {
            return;
        }
        let Some(i) = self
            .share_orphans
            .iter()
            .position(|o| !o.block && o.share.meta().map(|m| m.prev_share) == Some(missing))
        else {
            return;
        };
        let o = self.share_orphans.remove(i);
        // pasa por la cola como cualquier share (si aún falta su bloque padre vuelve a retenerse);
        // `base_ids` recuerda que debe admitirse como base
        self.base_ids.insert(o.share.id());
        self.share_queue.push_front((o.peer, o.share));
    }

    /// Valida shares pendientes (para que el bucle de E/S lo llame sin esperar al siguiente evento).
    pub fn work(&mut self, now: u64) -> Vec<Action> {
        self.now = now;
        self.step_shares();
        std::mem::take(&mut self.out)
    }

    /// Llegó un bloque nuevo: los shares que esperaban a su padre se reintentan.
    fn requeue_block_orphans(&mut self) {
        if self.share_orphans.iter().all(|o| !o.block) {
            return;
        }
        let (ready, rest): (Vec<ShareOrphan>, Vec<ShareOrphan>) =
            std::mem::take(&mut self.share_orphans).into_iter().partition(|o| o.block);
        self.share_orphans = rest;
        for o in ready {
            self.share_queue.push_back((o.peer, o.share));
        }
        self.orphan_asked.clear();
    }

    // ---------------------------------------------------------------- reloj

    /// Este proceso estuvo parado (no el par): reinicia los plazos para no desconectar a nadie
    /// por un silencio que fue nuestro.
    fn rebase_timers(&mut self, now: u64) {
        let gap = now.saturating_sub(self.last_event);
        self.log(format!("el nodo estuvo detenido {gap} s: reinicio los plazos de los pares"));
        for p in self.peers.values_mut() {
            p.connected_at = now;
            p.last_recv = now;
            p.last_ping_at = now;
            p.ping = None;
            for t in p.inflight_blocks.values_mut() {
                *t = now;
            }
            if let Some(s) = p.awaiting_headers_since.as_mut() {
                *s = now;
            }
            if let Some((_, s)) = p.awaiting_shares.as_mut() {
                *s = now;
            }
        }
    }

    fn on_tick(&mut self) {
        let now = self.now;
        self.bans.retain(|_, until| *until > now);
        self.failed.retain(|_, until| *until > now);
        let ids: Vec<PeerId> = self.peers.keys().copied().collect();
        for id in ids {
            let Some(p) = self.peers.get_mut(&id) else { continue };
            let mut dead = "";
            if !p.ready && now.saturating_sub(p.connected_at) > self.cfg.handshake_timeout {
                dead = "saludo sin terminar";
            }
            if now.saturating_sub(p.last_recv) > self.cfg.idle_timeout {
                dead = "sin actividad";
            }
            if let Some((_, sent)) = p.ping {
                if now.saturating_sub(sent) > self.cfg.pong_timeout {
                    dead = "no responde al ping";
                }
            }
            if p.inflight_blocks.values().any(|&t| now.saturating_sub(t) > self.cfg.block_timeout) {
                dead = "no entrega un bloque pedido";
            }
            if let Some(since) = p.awaiting_headers_since {
                if now.saturating_sub(since) > self.cfg.ids_timeout {
                    dead = "no entrega las cabeceras pedidas";
                }
            }
            if let Some((_, since)) = p.awaiting_shares {
                if now.saturating_sub(since) > self.cfg.ids_timeout {
                    dead = "no entrega los shares pedidos";
                }
            }
            if !dead.is_empty() {
                self.log(format!("motivo: {dead}"));
                self.disconnect(id);
                continue;
            }
            if p.ready && p.ping.is_none() && now.saturating_sub(p.last_ping_at) >= self.cfg.ping_interval {
                self.ping_counter += 1;
                let n = self.nonce ^ self.ping_counter.rotate_left(17);
                p.ping = Some((n, now));
                p.last_ping_at = now;
                self.send(id, Message::Ping(n));
            }
        }
        self.share_orphans.retain(|o| now.saturating_sub(o.since) <= SHARE_ORPHAN_TTL);
        self.step_headers();
        self.step_shares();
        self.retry_orphan_requests();
        self.maybe_sync();
        self.connect_more();
    }

    fn connect_more(&mut self) {
        let now = self.now;
        let outbound = self.peers.values().filter(|p| !p.inbound).count() + self.connecting.len();
        if outbound >= self.cfg.max_outbound {
            return;
        }
        let in_use: HashSet<AddrKey> = self.peers.values().filter(|p| !p.inbound).map(|p| key(&p.addr)).collect();
        let used_ips: HashSet<[u8; 16]> = self.peers.values().filter(|p| !p.inbound).map(|p| p.addr.ip).collect();
        let mut cands: Vec<NetAddr> = self
            .addrbook
            .values()
            .filter(|a| {
                let k = key(a);
                !in_use.contains(&k)
                    && !self.connecting.contains(&k)
                    && self.failed.get(&k).map_or(true, |&u| u <= now)
                    && !self.is_banned(&a.ip)
                    && !used_ips.contains(&a.ip)
            })
            .copied()
            .collect();
        cands.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then(key(a).cmp(&key(b))));
        for a in cands.into_iter().take(self.cfg.max_outbound - outbound) {
            self.connecting.insert(key(&a));
            self.out.push(Action::Connect(a));
        }
    }
}
