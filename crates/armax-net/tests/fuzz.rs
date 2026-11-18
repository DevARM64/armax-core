//! Pruebas de estrés con entradas malformadas, deterministas (semilla fija).
//!
//! 1. Códec: se muta el *payload* de cada mensaje válido y se recalcula el checksum para que
//!    la trama llegue entera hasta el decodificador. Nunca debe haber pánico; y lo que decodifica
//!    debe ser canónico (volver a codificarlo y decodificarlo da lo mismo).
//! 2. Flujo: basura aleatoria en trozos de tamaño aleatorio; el decodificador termina y no acumula
//!    más de una trama.
//! 3. Nodo: lo que sobrevive a la mutación (bloques, txs, shares, cabeceras con campos absurdos) se
//!    entrega a un `Node` real tras un apretón válido. Nunca debe haber pánico y el nodo debe seguir
//!    contestando.

use armax_chain::block::genesis_block;
use armax_chain::block::{Coinbase, Output};
use armax_chain::{Address, DamperParams, SkipPow};
use armax_keys::ed25519::Keypair;
use armax_keys::tx::{OutPoint, Transaction, TxOut};
use armax_ledger::Ledger;
use armax_mempool::{Mempool, MempoolConfig};
use armax_net::codec::*;
use armax_net::node::*;
use armax_pow::U256;
use armax_share::{make_extra, Share};
use armax_vm::sha256::sha256;

const T0: u64 = 1_800_000_000;
const NOW: u64 = T0 + 100_000_000;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 24) as u8
    }
}

fn ledger() -> Ledger {
    Ledger::new(DamperParams::MAINNET, genesis_block(T0, b"fuzz"), 1).unwrap()
}

fn headers(n: usize) -> Vec<armax_pow::BlockHeader> {
    (0..n)
        .map(|i| armax_pow::BlockHeader {
            version: 1,
            height: i as u64,
            prev_hash: [i as u8; 32],
            merkle_root: [7; 32],
            timestamp: 1_000 + i as u64,
            target: U256::from_u64(1 << 40),
            nonce: i as u64 * 3,
        })
        .collect()
}

fn sample_share(i: u8) -> Share {
    let mut header = headers(1).remove(0);
    header.nonce = i as u64;
    let coinbase = Coinbase {
        height: 1,
        fees: 0,
        outputs: vec![
            Output { address: Address([1; 32]), share_ppm: 600_000, amount: 15 },
            Output { address: Address([2; 32]), share_ppm: 400_000, amount: 10 },
        ],
        extra: make_extra(&[i; 32], &Address([3; 32])),
    };
    Share { header, coinbase, txs: vec![] }
}

/// Mensajes válidos de todos los tipos; el bloque cuelga del génesis del `ledger()` de arriba.
fn samples() -> Vec<Message> {
    let mut l = ledger();
    let fb = l.build_template(&[(Address([3; 32]), 1_000_000)], T0 + 300, vec![1, 2, 3], &[]).unwrap();
    let kp = Keypair::from_seed([5; 32]);
    let tx = Transaction::build_signed(
        &[(OutPoint { txid: [8; 32], index: 1 }, &kp)],
        vec![TxOut { address: Address([4; 32]), amount: 1234 }],
        &[0; 32],
    )
    .unwrap();
    let ids = vec![[1u8; 32], [2; 32], [3; 32]];
    vec![
        Message::Version(Version {
            protocol: PROTOCOL_VERSION,
            services: SERVICE_SERVE,
            genesis: [1; 32],
            tip: [2; 32],
            tip_height: 777,
            tip_work: U256::from_u64(123_456_789),
            nonce: 99,
            listen_port: 8333,
        }),
        Message::Verack,
        Message::Ping(5),
        Message::Pong(6),
        Message::GetAddr,
        Message::Addr(vec![NetAddr::v4(1, 2, 3, 4, 8000), NetAddr::v4(5, 6, 7, 8, 9)]),
        Message::GetHeaders { locator: ids.clone() },
        Message::Headers(headers(3)),
        Message::GetBlocks(ids.clone()),
        Message::Block(Box::new(fb)),
        Message::NotFound(ids.clone()),
        Message::InvBlocks(ids.clone()),
        Message::InvTxs(ids.clone()),
        Message::GetTxs(ids),
        Message::Tx(Box::new(tx)),
        Message::InvShares(vec![[7; 32], [8; 32]]),
        Message::GetShareChain { from: [9; 32], max: 64 },
        Message::Shares(vec![sample_share(1), sample_share(2)]),
    ]
}

/// Trama con el checksum y la longitud correctos para un payload arbitrario.
fn frame(cmd: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(FRAME_HEADER + payload.len());
    f.extend_from_slice(&MAGIC);
    f.push(cmd);
    f.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    f.extend_from_slice(&sha256(payload)[..4]);
    f.extend_from_slice(payload);
    f
}

/// Muta un payload: cambia bytes, inserta, borra, trunca o alarga.
fn mutate(rng: &mut Rng, payload: &[u8]) -> Vec<u8> {
    let mut p = payload.to_vec();
    match rng.below(6) {
        0 => {
            for _ in 0..1 + rng.below(4) {
                if !p.is_empty() {
                    let i = rng.below(p.len());
                    p[i] = rng.byte();
                }
            }
        }
        1 => {
            if !p.is_empty() {
                let i = rng.below(p.len());
                p[i] ^= 1 << rng.below(8);
            }
        }
        2 => p.truncate(rng.below(p.len() + 1)),
        3 => {
            for _ in 0..1 + rng.below(8) {
                p.push(rng.byte());
            }
        }
        4 => {
            if !p.is_empty() {
                let i = rng.below(p.len());
                p.remove(i);
            }
        }
        _ => {
            // valores extremos en una palabra de 4 u 8 bytes (longitudes y cuentas)
            if p.len() >= 8 {
                let i = rng.below(p.len() - 7);
                let v: [u8; 8] = if rng.below(2) == 0 { [0xFF; 8] } else { [0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0x7F] };
                p[i..i + 8].copy_from_slice(&v);
            }
        }
    }
    p
}

/// (cmd, payload) de un mensaje válido.
fn split(m: &Message) -> (u8, Vec<u8>) {
    let f = m.encode();
    (f[4], f[FRAME_HEADER..].to_vec())
}

#[test]
fn mutated_payloads_never_panic_and_stay_canonical() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut decoded = 0usize;
    let mut rejected = 0usize;
    for m in samples() {
        let (cmd, payload) = split(&m);
        for _ in 0..4000 {
            let p = mutate(&mut rng, &payload);
            match decode_one(&frame(cmd, &p)) {
                Ok(m2) => {
                    decoded += 1;
                    // lo que se acepta debe volver a codificarse a lo mismo
                    assert_eq!(decode_one(&m2.encode()), Ok(m2.clone()), "no canónico: {m2:?}");
                }
                Err(_) => rejected += 1,
            }
        }
    }
    eprintln!("payloads mutados: {decoded} aceptados, {rejected} rechazados");
    assert!(rejected > 1000, "la mutación debería romper muchos mensajes");
}

#[test]
fn random_payloads_for_every_command_never_panic() {
    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    for cmd in 0u8..=40 {
        for len in [0usize, 1, 2, 3, 7, 8, 9, 31, 32, 33, 64, 100, 513, 4096] {
            for _ in 0..40 {
                let p: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
                let _ = decode_one(&frame(cmd, &p));
            }
        }
    }
}

#[test]
fn garbage_streams_end_and_stay_bounded() {
    let mut rng = Rng(0x1234_5678_9ABC_DEF1);
    for round in 0..300 {
        let mut d = Decoder::new();
        let total = 1 + rng.below(20_000);
        let mut sent = 0;
        let mut stopped = false;
        while sent < total && !stopped {
            let n = (1 + rng.below(700)).min(total - sent);
            // una de cada tres veces, basura que empieza con el magic y un comando plausible
            let mut chunk: Vec<u8> = (0..n).map(|_| rng.byte()).collect();
            if round % 3 == 0 && sent == 0 && n > 5 {
                chunk[..4].copy_from_slice(&MAGIC);
                chunk[4] = 1 + (rng.byte() % 18);
            }
            sent += n;
            d.push(&chunk);
            loop {
                match d.next() {
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(_) => {
                        stopped = true; // el transporte cierra la conexión al primer error
                        break;
                    }
                }
            }
            assert!(d.buffered() <= FRAME_HEADER + MAX_PAYLOAD + 700, "buffer sin acotar");
        }
    }
}

fn node() -> Node {
    let cfg = NodeConfig { serve: true, listen_port: 8000, ..NodeConfig::default() };
    Node::new(ledger(), Mempool::new(MempoolConfig::default()), None, Box::new(SkipPow), cfg, 4242)
}

fn handshake(n: &mut Node, peer: PeerId, now: u64) {
    let genesis = n.ledger().chain().genesis_id();
    let addr = NetAddr::v4(10, 0, (peer >> 8) as u8, peer as u8, 40_000);
    n.handle(now, Event::Connected { peer, addr, inbound: true });
    n.handle(
        now,
        Event::Message(
            peer,
            Message::Version(Version {
                protocol: PROTOCOL_VERSION,
                services: 0,
                genesis,
                tip: genesis,
                tip_height: 0,
                tip_work: U256::from_u64(1),
                nonce: 1_000_000 + peer,
                listen_port: 0,
            }),
        ),
    );
    n.handle(now, Event::Message(peer, Message::Verack));
}

#[test]
fn the_node_survives_mutated_messages_from_a_handshaked_peer() {
    let mut rng = Rng(0xA5A5_5A5A_C3C3_3C3C);
    let mut n = node();
    let msgs = samples();
    let mut delivered = 0usize;
    let mut peer: PeerId = 1;
    let mut now = NOW;
    for _round in 0..6000 {
        let m = &msgs[rng.below(msgs.len())];
        if matches!(m, Message::Version(_) | Message::Verack) && rng.below(4) != 0 {
            continue;
        }
        let (cmd, payload) = split(m);
        let p = if rng.below(8) == 0 { payload } else { mutate(&mut rng, &payload) };
        let Ok(msg) = decode_one(&frame(cmd, &p)) else { continue };
        // cada pocas entregas, un par nuevo (el anterior pudo ser desconectado o castigado)
        if _round % 5 == 0 {
            peer += 1;
            n.handle(now, Event::Disconnected(peer - 1));
            handshake(&mut n, peer, now);
        }
        now += 1 + rng.below(40) as u64;
        n.handle(now, Event::Message(peer, msg));
        delivered += 1;
        if _round % 50 == 0 {
            n.handle(now, Event::Tick);
        }
    }
    eprintln!("mensajes mutados entregados al nodo: {delivered}");
    assert!(delivered > 500);

    // el nodo sigue vivo y responde
    peer += 1;
    handshake(&mut n, peer, now);
    let acts = n.handle(now, Event::Message(peer, Message::Ping(777)));
    assert!(
        acts.iter().any(|a| matches!(a, Action::Send(p, Message::Pong(777)) if *p == peer)),
        "el nodo ya no responde: {acts:?}"
    );
    // y su libro mayor sigue siendo coherente
    assert!(n.ledger().tip_height() < 1000);
}
