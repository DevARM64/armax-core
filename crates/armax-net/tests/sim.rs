//! Redes simuladas en memoria: varios `Node` conectados por una cola de eventos determinista.

use std::collections::{HashMap, VecDeque};

use armax_chain::block::genesis_block;
use armax_chain::{Address, DamperParams, FullPow, PowCheck, SharePowCheck, SkipPow, COIN};
use armax_pow::{BlockHeader, HeaderError};
use armax_share::{AddShare, Share, ShareParams};
use armax_keys::address::address_from_public_key;
use armax_keys::ed25519::Keypair;
use armax_keys::tx::{OutPoint, Transaction, TxOut};
use armax_ledger::{FullBlock, Ledger};
use armax_mempool::{Mempool, MempoolConfig};
use armax_net::codec::*;
use armax_net::node::*;

const T0: u64 = 1_800_000_000;
const NOW: u64 = T0 + 100_000_000;

fn addr_of(i: usize) -> NetAddr {
    NetAddr::v4(10, 0, 0, i as u8 + 1, 8000)
}
fn index_of(a: &NetAddr) -> usize {
    a.ip[15] as usize - 1
}

fn make_node(i: usize, serve: bool, seeds: Vec<NetAddr>, genesis_msg: &[u8]) -> Node {
    make_node_with(i, serve, seeds, genesis_msg, Box::new(SkipPow), 100_000)
}

fn make_node_with(
    i: usize,
    serve: bool,
    seeds: Vec<NetAddr>,
    genesis_msg: &[u8],
    pow: Box<dyn FullPow + Send>,
    headers_per_step: usize,
) -> Node {
    let ledger = Ledger::new(DamperParams::MAINNET, genesis_block(T0, genesis_msg), 1).unwrap();
    let cfg = NodeConfig {
        serve,
        listen_port: 8000,
        external_addr: if serve { Some(addr_of(i)) } else { None },
        seeds,
        headers_per_step,
        ..NodeConfig::default()
    };
    Node::new(ledger, Mempool::new(MempoolConfig::default()), None, pow, cfg, 1000 + i as u64)
}

struct Net {
    nodes: Vec<Node>,
    now: u64,
    links: HashMap<(usize, PeerId), (usize, PeerId)>,
    next_peer: u64,
    queue: VecDeque<(usize, Event)>,
    msgs: usize,
}

impl Net {
    fn new(nodes: Vec<Node>) -> Net {
        Net { nodes, now: NOW, links: HashMap::new(), next_peer: 1, queue: VecDeque::new(), msgs: 0 }
    }

    /// `a` marca a `b`.
    fn connect(&mut self, a: usize, b: usize) {
        let (pa, pb) = (self.next_peer, self.next_peer + 1);
        self.next_peer += 2;
        self.links.insert((a, pa), (b, pb));
        self.links.insert((b, pb), (a, pa));
        let mut from_a = addr_of(a);
        from_a.port = 40_000 + pa as u16; // puerto efímero visto por b
        self.queue.push_back((a, Event::Connected { peer: pa, addr: addr_of(b), inbound: false }));
        self.queue.push_back((b, Event::Connected { peer: pb, addr: from_a, inbound: true }));
    }

    fn apply(&mut self, i: usize, actions: Vec<Action>) {
        for act in actions {
            match act {
                Action::Send(p, m) => {
                    if let Some(&(j, q)) = self.links.get(&(i, p)) {
                        self.queue.push_back((j, Event::Message(q, m)));
                    }
                }
                Action::Disconnect(p) => {
                    if let Some((j, q)) = self.links.remove(&(i, p)) {
                        self.links.remove(&(j, q));
                        self.queue.push_back((j, Event::Disconnected(q)));
                    }
                }
                Action::Connect(a) => {
                    let j = index_of(&a);
                    if j < self.nodes.len() {
                        self.connect(i, j);
                    } else {
                        self.queue.push_back((i, Event::ConnectFailed(a)));
                    }
                }
            }
        }
    }

    fn run(&mut self) {
        while let Some((i, ev)) = self.queue.pop_front() {
            self.msgs += 1;
            assert!(self.msgs < 5_000_000, "la red no se estabiliza");
            let acts = self.nodes[i].handle(self.now, ev);
            self.apply(i, acts);
        }
    }

    fn tick(&mut self, secs: u64) {
        for _ in 0..secs {
            self.now += 1;
            for i in 0..self.nodes.len() {
                self.queue.push_back((i, Event::Tick));
            }
            self.run();
        }
    }

    /// El nodo `i` mina `n` bloques vacíos (con la clave `i`) y los anuncia.
    fn mine(&mut self, i: usize, n: usize) {
        for _ in 0..n {
            let h = self.nodes[i].ledger().tip_height() + 1;
            let miner = Address([i as u8 + 1; 32]);
            let fb = self.nodes[i]
                .ledger_mut()
                .build_template(&[(miner, 1_000_000)], T0 + h * 300, vec![i as u8], &[])
                .unwrap();
            let (r, acts) = self.nodes[i].submit_block(self.now, fb);
            r.unwrap();
            self.apply(i, acts);
            self.run();
        }
    }

    fn tips(&self) -> Vec<[u8; 32]> {
        self.nodes.iter().map(|n| n.ledger().tip_id()).collect()
    }
}

fn all_equal(v: &[[u8; 32]]) -> bool {
    v.windows(2).all(|w| w[0] == w[1])
}

#[test]
fn a_fresh_node_syncs_a_short_chain() {
    let mut net = Net::new(vec![make_node(0, true, vec![], b"net"), make_node(1, false, vec![], b"net")]);
    net.mine(0, 30);
    net.connect(1, 0);
    net.run();
    assert_eq!(net.nodes[1].ledger().tip_height(), 30);
    assert!(all_equal(&net.tips()));
    assert_eq!(net.nodes[1].ready_peer_count(), 1);
    assert!(!net.nodes[1].is_syncing());
}

#[test]
fn initial_download_spans_several_header_batches() {
    let mut net = Net::new(vec![make_node(0, true, vec![], b"net"), make_node(1, false, vec![], b"net")]);
    net.mine(0, 1_250); // 3 tramos de cabeceras (500 + 500 + 250)
    net.connect(1, 0);
    net.run();
    assert_eq!(net.nodes[1].ledger().tip_height(), 1_250);
    assert!(all_equal(&net.tips()));
    let (u, e) = net.nodes[1].ledger().supply();
    assert_eq!(u as i128, e);
}

#[test]
fn new_blocks_propagate_through_a_line_of_nodes() {
    let mut net = Net::new(vec![
        make_node(0, true, vec![], b"net"),
        make_node(1, true, vec![], b"net"),
        make_node(2, false, vec![], b"net"),
    ]);
    net.connect(1, 0);
    net.connect(2, 1);
    net.run();
    net.mine(0, 3);
    assert_eq!(net.nodes[2].ledger().tip_height(), 3);
    assert!(all_equal(&net.tips()));
}

#[test]
fn transactions_are_relayed_and_leave_the_pool_when_mined() {
    let mut net = Net::new(vec![
        make_node(0, true, vec![], b"net"),
        make_node(1, true, vec![], b"net"),
        make_node(2, false, vec![], b"net"),
    ]);
    net.connect(1, 0);
    net.connect(2, 1);
    net.run();
    // nodo 0 mina 110 bloques para la clave 1; la dirección del minero debe ser la de una clave real
    let kp = Keypair::from_seed([7; 32]);
    let me = address_from_public_key(&kp.public_key());
    for _ in 0..110 {
        let h = net.nodes[0].ledger().tip_height() + 1;
        let fb = net.nodes[0].ledger_mut().build_template(&[(me, 1_000_000)], T0 + h * 300, vec![], &[]).unwrap();
        let (r, acts) = net.nodes[0].submit_block(net.now, fb);
        r.unwrap();
        net.apply(0, acts);
        net.run();
    }
    assert_eq!(net.nodes[2].ledger().tip_height(), 110);
    let first = net.nodes[0].ledger().chain().main_chain()[1];
    let cb = net.nodes[0].ledger().chain().coinbase_of(&first).unwrap().id();
    let tx = Transaction::build_signed(
        &[(OutPoint { txid: cb, index: 0 }, &kp)],
        vec![TxOut { address: Address([9; 32]), amount: 25 * COIN - 5_000 }],
        &net.nodes[0].ledger().chain_id(),
    )
    .unwrap();
    let txid = tx.txid();
    let (r, acts) = net.nodes[2].submit_tx(net.now, tx);
    r.unwrap();
    net.apply(2, acts);
    net.run();
    for i in 0..3 {
        assert!(net.nodes[i].pool().contains(&txid), "nodo {i}");
    }
    // el nodo 0 la incluye en un bloque
    let cands = net.nodes[0].pool().candidates();
    let h = net.nodes[0].ledger().tip_height() + 1;
    let fb = net.nodes[0].ledger_mut().build_template(&[(me, 1_000_000)], T0 + h * 300, vec![], &cands).unwrap();
    assert_eq!(fb.txs.len(), 1);
    let (r, acts) = net.nodes[0].submit_block(net.now, fb);
    r.unwrap();
    net.apply(0, acts);
    net.run();
    for i in 0..3 {
        assert!(net.nodes[i].pool().is_empty(), "nodo {i}");
        assert_eq!(net.nodes[i].ledger().balance_of(&Address([9; 32])), (25 * COIN - 5_000) as u128);
    }
    assert!(all_equal(&net.tips()));
}

#[test]
fn partitions_converge_on_the_branch_with_more_work() {
    let mut net = Net::new(vec![make_node(0, true, vec![], b"net"), make_node(1, true, vec![], b"net")]);
    net.mine(0, 5);
    net.mine(1, 8);
    assert!(!all_equal(&net.tips()));
    net.connect(0, 1);
    net.run();
    assert!(all_equal(&net.tips()));
    assert_eq!(net.nodes[0].ledger().tip_height(), 8);
    for n in &net.nodes {
        let (u, e) = n.ledger().supply();
        assert_eq!(u as i128, e);
    }
}

#[test]
fn a_node_on_another_network_is_refused_and_banned() {
    let mut net = Net::new(vec![make_node(0, true, vec![], b"net"), make_node(1, true, vec![], b"otra red")]);
    net.connect(1, 0);
    net.run();
    assert_eq!(net.nodes[0].peer_count(), 0);
    assert_eq!(net.nodes[1].peer_count(), 0);
    assert!(net.nodes[0].is_banned(&addr_of(1).ip));
}

#[test]
fn connecting_to_yourself_is_detected() {
    let mut net = Net::new(vec![make_node(0, true, vec![], b"net")]);
    // el nodo se marca a sí mismo: ambos extremos son el mismo nodo
    net.connect(0, 0);
    net.run();
    assert_eq!(net.nodes[0].peer_count(), 0);
    assert!(!net.nodes[0].is_banned(&addr_of(0).ip), "no se veta por conectarse a uno mismo");
}

#[test]
fn seeds_and_address_exchange_build_the_outbound_connections() {
    // 0 es la semilla; 1 y 2 la conocen; 3 solo conoce la semilla y debe descubrir a 1 y 2 por Addr
    let seeds = vec![addr_of(0)];
    let mut net = Net::new(vec![
        make_node(0, true, vec![], b"net"),
        make_node(1, true, seeds.clone(), b"net"),
        make_node(2, true, seeds.clone(), b"net"),
        make_node(3, false, seeds, b"net"),
    ]);
    net.tick(5);
    net.tick(5);
    assert!(net.nodes[3].known_addresses() >= 2, "{}", net.nodes[3].known_addresses());
    net.tick(5);
    assert!(net.nodes[3].ready_peer_count() >= 2);
    // un teléfono (serve=false) no se anuncia: nadie lo tiene en su libreta de direcciones
    for i in 0..3 {
        assert!(net.nodes[i].known_addresses() <= 3);
    }
}

#[test]
fn failed_connections_back_off() {
    let mut net = Net::new(vec![make_node(0, false, vec![NetAddr::v4(10, 9, 9, 99, 8000)], b"net")]);
    net.tick(1);
    // índice 98 no existe → ConnectFailed → no se reintenta de inmediato
    let mut connects = 0;
    for _ in 0..30 {
        net.now += 1;
        let acts = net.nodes[0].handle(net.now, Event::Tick);
        connects += acts.iter().filter(|a| matches!(a, Action::Connect(_))).count();
        net.apply(0, acts);
        net.run();
    }
    assert_eq!(connects, 0, "dentro del tiempo de espera no se reintenta");
    for _ in 0..60 {
        net.now += 1;
        let acts = net.nodes[0].handle(net.now, Event::Tick);
        connects += acts.iter().filter(|a| matches!(a, Action::Connect(_))).count();
        net.apply(0, acts);
        net.run();
    }
    assert!(connects >= 1);
}

#[test]
fn silent_peers_are_dropped_by_timeouts() {
    let mut net = Net::new(vec![make_node(0, true, vec![], b"net")]);
    // llega una conexión entrante y no dice nada
    let acts = net.nodes[0].handle(net.now, Event::Connected { peer: 77, addr: NetAddr::v4(10, 0, 0, 50, 5000), inbound: true });
    assert!(matches!(acts[0], Action::Send(77, Message::Version(_))));
    assert_eq!(net.nodes[0].peer_count(), 1);
    let mut dropped = false;
    for _ in 0..40 {
        net.now += 1;
        let acts = net.nodes[0].handle(net.now, Event::Tick);
        dropped |= acts.contains(&Action::Disconnect(77));
    }
    assert!(dropped);
    assert_eq!(net.nodes[0].peer_count(), 0);
}

// ---- un par malicioso conducido a mano -----------------------------------------------------

struct Manual {
    node: Node,
    now: u64,
    sent: Vec<Message>,
    disconnected: bool,
}
impl Manual {
    fn new() -> Manual {
        let mut m = Manual { node: make_node(0, true, vec![], b"net"), now: NOW, sent: vec![], disconnected: false };
        m.feed(Event::Connected { peer: 1, addr: NetAddr::v4(10, 0, 0, 77, 5000), inbound: true });
        let v = Version {
            protocol: PROTOCOL_VERSION,
            services: 0,
            genesis: m.node.ledger().chain().genesis_id(),
            tip: [5; 32],
            tip_height: 0,
            tip_work: armax_pow::U256::ZERO,
            nonce: 4242,
            listen_port: 0,
        };
        m.msg(Message::Version(v));
        m.msg(Message::Verack);
        m
    }
    fn feed(&mut self, ev: Event) {
        for a in self.node.handle(self.now, ev) {
            match a {
                Action::Send(1, m) => self.sent.push(m),
                Action::Disconnect(1) => self.disconnected = true,
                _ => {}
            }
        }
    }
    fn msg(&mut self, m: Message) {
        self.feed(Event::Message(1, m));
    }
}

fn some_block(node: &mut Node) -> FullBlock {
    let h = node.ledger().tip_height() + 1;
    node.ledger_mut().build_template(&[(Address([3; 32]), 1_000_000)], T0 + h * 300, vec![], &[]).unwrap()
}

#[test]
fn unsolicited_blocks_are_scored_and_end_in_a_ban() {
    let mut m = Manual::new();
    assert!(m.sent.iter().any(|x| matches!(x, Message::Verack)));
    let fb = some_block(&mut m.node);
    for _ in 0..4 {
        m.msg(Message::Block(Box::new(fb.clone())));
        assert!(!m.disconnected);
    }
    m.msg(Message::Block(Box::new(fb)));
    assert!(m.disconnected);
    assert!(m.node.is_banned(&NetAddr::v4(10, 0, 0, 77, 0).ip));
    assert_eq!(m.node.ledger().tip_height(), 0, "nada no pedido entra en la cadena");
}

#[test]
fn an_invalid_requested_block_bans_immediately() {
    let mut m = Manual::new();
    let mut fb = some_block(&mut m.node);
    let id = fb.id();
    fb.block.header.merkle_root = [1; 32]; // el id cambia: se pide el id correcto del bloque corrupto
    let bad_id = fb.id();
    assert_ne!(id, bad_id);
    m.msg(Message::InvBlocks(vec![bad_id]));
    assert!(m.sent.iter().any(|x| matches!(x, Message::GetBlocks(ids) if ids == &vec![bad_id])));
    m.msg(Message::Block(Box::new(fb)));
    assert!(m.disconnected);
    assert!(m.node.is_banned(&NetAddr::v4(10, 0, 0, 77, 0).ip));
}

#[test]
fn messages_before_the_handshake_are_not_tolerated() {
    let mut m = Manual {
        node: make_node(0, true, vec![], b"net"),
        now: NOW,
        sent: vec![],
        disconnected: false,
    };
    m.feed(Event::Connected { peer: 1, addr: NetAddr::v4(10, 0, 0, 78, 5000), inbound: true });
    m.msg(Message::GetAddr);
    assert!(m.disconnected);
}

#[test]
fn flooding_exhausts_the_rate_limit() {
    let mut m = Manual::new();
    for _ in 0..400 {
        if m.disconnected {
            break;
        }
        m.msg(Message::Ping(1));
    }
    assert!(m.disconnected);
}

#[test]
fn a_clock_skewed_block_is_not_punished() {
    let mut m = Manual::new();
    // bloque con timestamp muy en el futuro respecto al reloj del nodo
    let mut fb = some_block(&mut m.node);
    fb.block.header.timestamp = NOW + 10_000_000;
    let id = fb.id();
    m.msg(Message::InvBlocks(vec![id]));
    m.msg(Message::Block(Box::new(fb)));
    assert!(!m.disconnected);
    assert!(!m.node.is_banned(&NetAddr::v4(10, 0, 0, 77, 0).ip));
}

// ---- sincronización cabeceras-primero --------------------------------------------------------

/// PoW de mentira que cuenta cuántas veces se le consulta y rechaza las cabeceras con nonce ≠ 0.
struct CountingPow(std::sync::Arc<std::sync::atomic::AtomicUsize>);
impl PowCheck for CountingPow {
    fn check(&mut self, h: &BlockHeader, _: &[u8; 32]) -> Result<(), HeaderError> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if h.nonce != 0 {
            Err(HeaderError::InsufficientWork)
        } else {
            Ok(())
        }
    }
}

impl SharePowCheck for CountingPow {
    fn check_at(&mut self, _: &BlockHeader, _: &[u8; 32], _: &armax_pow::U256) -> Result<[u8; 32], HeaderError> {
        Ok([0; 32])
    }
}

/// Cabeceras de una cadena honesta de `n` bloques (nodo donante aparte).
fn donor_headers(n: usize) -> Vec<BlockHeader> {
    let mut d = make_node(9, true, vec![], b"net");
    for _ in 0..n {
        let fb = some_block(&mut d);
        let (r, _) = d.submit_block(NOW, fb);
        r.unwrap();
    }
    let c = d.ledger().chain();
    c.main_ids().iter().skip(1).map(|id| c.header(id).unwrap().clone()).collect()
}

impl Manual {
    /// Un par que dice tener muchísimo trabajo, para forzar la sincronización con él.
    fn claiming(node: Node) -> Manual {
        let mut m = Manual { node, now: NOW, sent: vec![], disconnected: false };
        m.feed(Event::Connected { peer: 1, addr: NetAddr::v4(10, 0, 0, 77, 5000), inbound: true });
        let v = Version {
            protocol: PROTOCOL_VERSION,
            services: 0,
            genesis: m.node.ledger().chain().genesis_id(),
            tip: [5; 32],
            tip_height: 1_000,
            tip_work: armax_pow::U256::from_u64(u64::MAX),
            nonce: 4242,
            listen_port: 0,
        };
        m.msg(Message::Version(v));
        m.msg(Message::Verack);
        assert!(m.sent.iter().any(|x| matches!(x, Message::GetHeaders { .. })), "debía pedir cabeceras");
        m
    }
    fn asked_for_bodies(&self) -> bool {
        self.sent.iter().any(|x| matches!(x, Message::GetBlocks(_)))
    }
}

#[test]
fn a_frozen_process_does_not_blame_its_peers_for_the_silence() {
    let node = make_node_with(0, true, vec![], b"net", Box::new(SkipPow), 3);
    let mut m = Manual::claiming(node); // ya pidió cabeceras y las espera
    // el sistema congela el proceso una hora (pantalla apagada) y al despertar llega un tic
    m.now += 3_600;
    m.feed(Event::Tick);
    assert!(!m.disconnected, "el silencio fue nuestro, no del par");
    // pero un par realmente mudo sigue cayendo por sus plazos normales
    for _ in 0..90 {
        m.now += 1;
        m.feed(Event::Tick);
    }
    assert!(m.disconnected, "un par que no contesta tras el despertar sí se desconecta");
}

#[test]
fn a_header_with_bad_pow_bans_the_peer_before_any_body_is_requested() {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let node = make_node_with(0, true, vec![], b"net", Box::new(CountingPow(calls.clone())), 100_000);
    let mut m = Manual::claiming(node);
    let mut hs = donor_headers(20);
    hs[10].nonce = 1; // PoW inválido en la cabecera 11
    m.msg(Message::Headers(hs));
    assert!(m.disconnected);
    assert!(m.node.is_banned(&NetAddr::v4(10, 0, 0, 77, 0).ip));
    assert!(!m.asked_for_bodies(), "no se debe pedir ningún cuerpo de una cadena con una cabecera falsa");
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 11, "se verificó hasta la primera mala");
    assert_eq!(m.node.ledger().tip_height(), 0);
    assert!(!m.node.is_syncing());
}

#[test]
fn headers_are_validated_in_small_steps_and_bodies_follow() {
    let node = make_node_with(0, true, vec![], b"net", Box::new(SkipPow), 3);
    let mut m = Manual::claiming(node);
    m.msg(Message::Headers(donor_headers(20)));
    assert!(!m.asked_for_bodies(), "tras el primer paso (3 de 20) aún no hay cuerpos");
    for _ in 0..3 {
        m.now += 1;
        m.feed(Event::Tick);
    }
    assert!(!m.asked_for_bodies(), "12 de 20 validadas: todavía no");
    for _ in 0..3 {
        m.now += 1;
        m.feed(Event::Tick);
    }
    assert!(m.asked_for_bodies(), "las 20 validadas: se piden los cuerpos");
    assert!(!m.disconnected);
}

#[test]
fn pow_runs_once_per_block_even_though_headers_come_first() {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut net = Net::new(vec![
        make_node(0, true, vec![], b"net"),
        make_node_with(1, false, vec![], b"net", Box::new(CountingPow(calls.clone())), 100_000),
    ]);
    net.mine(0, 40);
    net.connect(1, 0);
    net.run();
    assert_eq!(net.nodes[1].ledger().tip_height(), 40);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 40, "una verificación por bloque, no dos");
}

#[test]
fn headers_that_do_not_connect_get_a_mild_penalty_and_end_the_sync() {
    let mut m = Manual::claiming(make_node(0, true, vec![], b"net"));
    let hs = donor_headers(20);
    m.msg(Message::Headers(hs[5..].to_vec())); // su primera cabecera cuelga de algo que no tenemos
    assert!(!m.disconnected, "es una falta leve (puede ser una carrera legítima)");
    assert!(!m.node.is_banned(&NetAddr::v4(10, 0, 0, 77, 0).ip));
    assert!(!m.asked_for_bodies());
    assert!(!m.node.is_syncing());
}

#[test]
fn unlinked_headers_inside_a_batch_are_banned() {
    let mut m = Manual::claiming(make_node(0, true, vec![], b"net"));
    let mut hs = donor_headers(20);
    hs.remove(7); // salto en la mitad del lote
    m.msg(Message::Headers(hs));
    assert!(m.disconnected && m.node.is_banned(&NetAddr::v4(10, 0, 0, 77, 0).ip));
    assert!(!m.asked_for_bodies());
}

#[test]
fn headers_from_the_future_are_not_punished_and_not_followed() {
    let mut m = Manual::claiming(make_node(0, true, vec![], b"net"));
    m.now = T0; // nuestro reloj va muy por detrás de las cabeceras
    m.msg(Message::Headers(donor_headers(20)));
    assert!(!m.disconnected && !m.node.is_banned(&NetAddr::v4(10, 0, 0, 77, 0).ip));
    assert!(!m.asked_for_bodies());
    assert!(!m.node.is_syncing());
}

#[test]
fn unsolicited_headers_are_penalised() {
    let mut m = Manual::new();
    m.msg(Message::Headers(donor_headers(3)));
    m.msg(Message::Headers(donor_headers(3)));
    m.msg(Message::Headers(donor_headers(3)));
    m.msg(Message::Headers(donor_headers(3)));
    m.msg(Message::Headers(donor_headers(3)));
    assert!(m.disconnected, "cabeceras que no pedimos suman puntos hasta el veto");
    assert_eq!(m.node.ledger().tip_height(), 0);
}

// ---- sharechain ------------------------------------------------------------------------------

fn make_share_node(i: usize, serve: bool) -> Node {
    make_share_node_with(i, serve, ShareParams::FAST)
}

fn make_share_node_with(i: usize, serve: bool, p: ShareParams) -> Node {
    let mut n = make_node(i, serve, vec![], b"net");
    n.enable_sharechain(p);
    n
}

/// Share nuevo de la sharechain del nodo `node` sobre su punta de bloques (sin enviarlo).
fn craft_share(node: &Node, miner: u8) -> Share {
    let tip = node.ledger().tip_id();
    let h = node.ledger().tip_height() + 1;
    node.sharechain().unwrap().template(node.ledger().chain(), tip, Address([miner; 32]), T0 + h * 300).unwrap()
}

impl Net {
    /// El nodo `i` halla un share (con SkipPow cumple también el target del bloque) y lo difunde.
    fn mine_share(&mut self, i: usize) -> [u8; 32] {
        let sh = craft_share(&self.nodes[i], i as u8 + 1);
        let id = sh.id();
        let (r, acts) = self.nodes[i].submit_share(self.now, sh);
        assert!(matches!(r, Ok(AddShare::Added { .. })), "{r:?}");
        self.apply(i, acts);
        self.run();
        id
    }
}

#[test]
fn shares_are_relayed_and_become_blocks_everywhere() {
    let mut net = Net::new(vec![make_share_node(0, true), make_share_node(1, true), make_share_node(2, false)]);
    net.connect(1, 0);
    net.connect(2, 1);
    net.run();
    let mut last = [0u8; 32];
    for _ in 0..5 {
        last = net.mine_share(0);
    }
    for n in &net.nodes {
        assert_eq!(n.sharechain().unwrap().tip(), Some(last));
        assert_eq!(n.sharechain().unwrap().len(), 5);
        assert_eq!(n.share_orphan_count(), 0);
    }
    // cada share cumplía el target del bloque: también avanzó la cadena de bloques en todos
    assert_eq!(net.nodes[2].ledger().tip_height(), 5);
    assert!(all_equal(&net.tips()));
}

#[test]
fn a_late_joiner_backfills_the_whole_sharechain() {
    let mut net = Net::new(vec![make_share_node(0, true), make_share_node(1, false)]);
    for _ in 0..12 {
        net.mine_share(0);
    }
    assert_eq!(net.nodes[0].sharechain().unwrap().len(), 12);
    net.connect(1, 0);
    net.run();
    net.tick(5);
    assert_eq!(net.nodes[1].sharechain().unwrap().len(), 12);
    assert_eq!(net.nodes[1].sharechain().unwrap().tip(), net.nodes[0].sharechain().unwrap().tip());
    assert_eq!(net.nodes[1].share_orphan_count(), 0);
    assert_eq!(net.nodes[1].share_queue_len(), 0);
    assert!(all_equal(&net.tips()));
}

#[test]
fn nodes_without_a_sharechain_neither_get_nor_send_share_traffic() {
    let mut net = Net::new(vec![make_share_node(0, true), make_node(1, false, vec![], b"net")]);
    net.connect(1, 0);
    net.run();
    net.mine_share(0);
    assert!(net.nodes[1].sharechain().is_none());
    assert_eq!(net.nodes[1].ready_peer_count(), 1, "sin castigos ni desconexión");
    assert_eq!(net.nodes[0].ready_peer_count(), 1);
    // el bloque sí llega por la vía de siempre
    assert_eq!(net.nodes[1].ledger().tip_height(), 1);
}

/// Un par conducido a mano que anuncia `SERVICE_SHARES`.
impl Manual {
    fn sharing() -> Manual {
        let mut m = Manual { node: make_share_node(0, true), now: NOW, sent: vec![], disconnected: false };
        m.feed(Event::Connected { peer: 1, addr: NetAddr::v4(10, 0, 0, 77, 5000), inbound: true });
        let v = Version {
            protocol: PROTOCOL_VERSION,
            services: SERVICE_SHARES,
            genesis: m.node.ledger().chain().genesis_id(),
            tip: [5; 32],
            tip_height: 0,
            tip_work: armax_pow::U256::ZERO,
            nonce: 4242,
            listen_port: 0,
        };
        m.msg(Message::Version(v));
        m.msg(Message::Verack);
        m
    }
}

#[test]
fn a_share_whose_parent_block_is_unknown_is_held_then_resolved() {
    // donante: 1 bloque y un share encima (altura 2)
    let mut donor = make_share_node(9, true);
    let b1 = some_block(&mut donor);
    let b1_id = b1.id();
    donor.submit_block(NOW, b1).0.unwrap();
    let share = craft_share(&donor, 9);
    let sid = share.id();

    let mut m = Manual::sharing();
    assert!(m.sent.iter().any(|x| matches!(x, Message::Verack)));
    m.msg(Message::InvShares(vec![sid]));
    assert!(m.sent.iter().any(|x| matches!(x, Message::GetShareChain { from, max: 1 } if *from == sid)));
    m.msg(Message::Shares(vec![share]));
    // padre desconocido: retenido, sin castigo, y se pide el bloque que falta
    assert!(!m.disconnected);
    assert_eq!(m.node.share_orphan_count(), 1);
    assert!(m.sent.iter().any(|x| matches!(x, Message::GetBlocks(ids) if ids == &vec![b1_id])));
    assert_eq!(m.node.sharechain().unwrap().len(), 0);
    // llega el bloque pedido: el share se reintenta y entra (y, siendo bloque, la cadena avanza)
    let fb = donor.ledger().full_block(&b1_id).unwrap();
    m.msg(Message::Block(Box::new(fb)));
    assert!(!m.disconnected);
    assert_eq!(m.node.share_orphan_count(), 0);
    assert_eq!(m.node.sharechain().unwrap().len(), 1);
    assert_eq!(m.node.ledger().tip_height(), 2);
}

#[test]
fn an_invalid_share_bans_the_sender() {
    let donor = make_share_node(9, true);
    let mut share = craft_share(&donor, 9);
    share.header.merkle_root = [1; 32]; // ya no compromete al coinbase
    let sid = share.id();
    let mut m = Manual::sharing();
    m.msg(Message::InvShares(vec![sid]));
    m.msg(Message::Shares(vec![share]));
    assert!(m.disconnected);
    assert!(m.node.is_banned(&NetAddr::v4(10, 0, 0, 77, 0).ip));
    assert_eq!(m.node.sharechain().unwrap().len(), 0);
}

#[test]
fn unsolicited_share_batches_are_scored_and_end_in_a_ban() {
    let donor = make_share_node(9, true);
    let share = craft_share(&donor, 9);
    let mut m = Manual::sharing();
    for _ in 0..4 {
        m.msg(Message::Shares(vec![share.clone()]));
        assert!(!m.disconnected);
    }
    m.msg(Message::Shares(vec![share]));
    assert!(m.disconnected);
    assert_eq!(m.node.sharechain().unwrap().len(), 0, "nada no pedido entra");
}

#[test]
fn a_batch_that_is_not_the_requested_chain_is_rejected() {
    let donor = make_share_node(9, true);
    let a = craft_share(&donor, 9);
    let b = craft_share(&donor, 8); // otro share distinto
    let mut m = Manual::sharing();
    m.msg(Message::InvShares(vec![a.id()]));
    m.msg(Message::Shares(vec![b])); // el último no es el pedido
    assert!(!m.disconnected); // castigo leve
    assert_eq!(m.node.sharechain().unwrap().len(), 0);
    assert_eq!(m.node.share_queue_len(), 0);
}

#[test]
fn a_node_without_sharechain_scores_share_announcements() {
    let mut m = Manual::new();
    for _ in 0..4 {
        m.msg(Message::InvShares(vec![[1; 32]]));
        assert!(!m.disconnected);
    }
    m.msg(Message::InvShares(vec![[1; 32]]));
    assert!(m.disconnected);
}

#[test]
fn a_late_joiner_backfills_more_shares_than_the_old_orphan_cap() {
    // 300 shares (ventana FAST = 256): hay que retener toda la rama que se pide hacia atrás
    let mut net = Net::new(vec![make_share_node(0, true), make_share_node(1, false)]);
    for _ in 0..300 {
        net.mine_share(0);
    }
    net.connect(1, 0);
    net.run();
    for _ in 0..60 {
        net.tick(1);
        if net.nodes[1].sharechain().unwrap().len() == 300 {
            break;
        }
    }
    assert_eq!(net.nodes[1].sharechain().unwrap().len(), 300);
    assert_eq!(net.nodes[1].sharechain().unwrap().tip(), net.nodes[0].sharechain().unwrap().tip());
    assert_eq!(net.nodes[1].share_orphan_count(), 0);
}

#[test]
fn a_joiner_starts_at_the_horizon_when_the_peer_has_pruned_the_root() {
    let p = ShareParams { ratio: 4, window: 16 };
    let mut net = Net::new(vec![make_share_node_with(0, true, p), make_share_node_with(1, false, p)]);
    for _ in 0..150 {
        net.mine_share(0);
    }
    let kept = net.nodes[0].sharechain().unwrap().len();
    assert!(kept < 150, "A debió podar: {kept}");
    net.connect(1, 0);
    net.run();
    for _ in 0..60 {
        net.tick(1);
        if net.nodes[1].share_orphan_count() == 0 && net.nodes[1].share_queue_len() == 0 {
            break;
        }
    }
    assert_eq!(net.nodes[1].share_orphan_count(), 0);
    assert_eq!(net.nodes[1].sharechain().unwrap().tip(), net.nodes[0].sharechain().unwrap().tip());
    // y a partir de aquí sigue la sharechain con validación completa
    for _ in 0..5 {
        net.mine_share(0);
    }
    assert_eq!(net.nodes[1].sharechain().unwrap().tip(), net.nodes[0].sharechain().unwrap().tip());
    assert_eq!(net.nodes[1].ready_peer_count(), 1, "sin castigos");
    // y B también puede aportar shares que A acepta
    net.mine_share(1);
    assert_eq!(net.nodes[0].sharechain().unwrap().tip(), net.nodes[1].sharechain().unwrap().tip());
}

// ---- shares con transacciones ----------------------------------------------------------------

/// PoW de mentira para shares: acepta todo y su digest nunca cumple el target del bloque (así los
/// shares con transacciones inventadas no se publican como bloques).
struct NeverBlockPow;
impl PowCheck for NeverBlockPow {
    fn check(&mut self, _: &BlockHeader, _: &[u8; 32]) -> Result<(), HeaderError> {
        Ok(())
    }
}
impl SharePowCheck for NeverBlockPow {
    fn check_at(&mut self, _: &BlockHeader, _: &[u8; 32], _: &armax_pow::U256) -> Result<[u8; 32], HeaderError> {
        Ok([0xff; 32])
    }
}

/// Transacciones gruesas (64 entradas, ~8.5 KB cada una) con entradas ficticias: la sharechain no
/// ejecuta transacciones, solo exige que decodifiquen y que la raíz de Merkle las compromita.
fn fat_txs(seed: u8, n: usize) -> Vec<Transaction> {
    let kp = Keypair::from_seed([3; 32]);
    (0..n)
        .map(|t| {
            let ins: Vec<(OutPoint, &Keypair)> =
                (0..64u32).map(|j| (OutPoint { txid: [seed.wrapping_add(t as u8); 32], index: j }, &kp)).collect();
            Transaction::build_signed(&ins, vec![TxOut { address: Address([4; 32]), amount: 1 }], &[0u8; 32]).unwrap()
        })
        .collect()
}

#[test]
fn share_batches_with_big_transactions_stay_under_the_byte_budget_and_end_at_the_requested_share() {
    let mut node = make_node_with(0, true, vec![], b"net", Box::new(NeverBlockPow), 100_000);
    node.enable_sharechain(ShareParams::FAST);
    let tip = node.ledger().tip_id();
    let mut last = [0u8; 32];
    for i in 0..30u8 {
        let sh = node
            .sharechain()
            .unwrap()
            .template_with(node.ledger().chain(), tip, Address([i % 3 + 1; 32]), T0 + 300, fat_txs(i, 7), 0)
            .unwrap();
        last = sh.id();
        assert!(sh.to_bytes().len() > 50_000, "el share debía ser grueso");
        let (r, _) = node.submit_share(NOW, sh);
        assert!(matches!(r, Ok(AddShare::Added { .. })), "{r:?}");
    }
    assert_eq!(node.sharechain().unwrap().len(), 30);

    let mut m = Manual { node, now: NOW, sent: vec![], disconnected: false };
    m.feed(Event::Connected { peer: 1, addr: NetAddr::v4(10, 0, 0, 77, 5000), inbound: true });
    m.msg(Message::Version(Version {
        protocol: PROTOCOL_VERSION,
        services: SERVICE_SHARES,
        genesis: m.node.ledger().chain().genesis_id(),
        tip: [5; 32],
        tip_height: 0,
        tip_work: armax_pow::U256::ZERO,
        nonce: 4242,
        listen_port: 0,
    }));
    m.msg(Message::Verack);
    m.msg(Message::GetShareChain { from: last, max: 64 });
    let batch = m.sent.iter().rev().find_map(|x| if let Message::Shares(l) = x { Some(l.clone()) } else { None }).unwrap();
    let bytes: usize = batch.iter().map(|s| s.to_bytes().len()).sum();
    assert!(batch.len() >= 2 && batch.len() < 30, "len={}", batch.len());
    assert!(bytes <= 1024 * 1024 + 70_000, "bytes={bytes}");
    assert_eq!(batch.last().unwrap().id(), last, "el lote debe terminar en el share pedido");
    let linked = batch.windows(2).all(|w| w[1].meta().unwrap().prev_share == w[0].id());
    assert!(linked);
    // y el mensaje se codifica sin pasar del máximo
    assert!(Message::Shares(batch).encode().len() <= MAX_PAYLOAD + 64);
}
