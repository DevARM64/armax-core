//! Pruebas de `shares.db`: ida y vuelta, cola rota, otra red, compactación.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use armax_chain::block::genesis_block;
use armax_chain::{AddOutcome, Address, Chain, DamperParams, SkipPow};
use armax_pow::consensus::TARGET_BLOCK_TIME;
use armax_share::{AddShare, ShareChain, ShareParams, ShareStore, ShareStoreError};

type Hash32 = [u8; 32];

const T0: u64 = 1_800_000_000;
const NOW: u64 = T0 + 1_000_000;
const PARAMS: ShareParams = ShareParams { ratio: 4, window: 8 };

fn addr(i: u8) -> Address {
    Address([i; 32])
}

fn chain_with(n: usize, msg: &[u8]) -> (Chain, Vec<Hash32>) {
    let mut chain = Chain::new(DamperParams::MAINNET, genesis_block(T0, msg)).unwrap();
    let mut ids = vec![chain.genesis_id()];
    for i in 1..=n {
        let b = chain.build_template(ids.last().unwrap(), addr(200), T0 + i as u64 * TARGET_BLOCK_TIME, vec![]).unwrap();
        let id = b.id();
        assert!(matches!(chain.add_block(b, NOW, &mut SkipPow), Ok(AddOutcome::Extended)));
        ids.push(id);
    }
    (chain, ids)
}

fn path(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("armax-shares-{}-{}.db", std::process::id(), name));
    let _ = fs::remove_file(&p);
    p
}

/// Abre el archivo (nuevo) y mete `n` shares: devuelve la sharechain y el almacén.
fn fill(p: &PathBuf, chain: &Chain, parent: Hash32, n: u32) -> (ShareChain, ShareStore) {
    let mut sc = ShareChain::new(PARAMS);
    let (mut st, rep) = ShareStore::open(p, chain, &mut sc, NOW, &mut SkipPow).unwrap();
    assert_eq!(rep.loaded, 0);
    let ts = chain.header(&parent).unwrap().timestamp + TARGET_BLOCK_TIME;
    for i in 0..n {
        let t = sc.template(chain, parent, addr((i % 5) as u8 + 1), ts).unwrap();
        assert!(matches!(sc.add(t.clone(), chain, NOW, &mut SkipPow), Ok(AddShare::Added { .. })));
        st.append(&t).unwrap();
    }
    (sc, st)
}

fn reopen(p: &PathBuf, chain: &Chain) -> (ShareChain, ShareStore, armax_share::ShareLoadReport) {
    let mut sc = ShareChain::new(PARAMS);
    let (st, rep) = ShareStore::open(p, chain, &mut sc, NOW, &mut SkipPow).unwrap();
    (sc, st, rep)
}

#[test]
fn shares_survive_a_restart() {
    let (chain, ids) = chain_with(2, b"s");
    let p = path("roundtrip");
    let (sc, st) = fill(&p, &chain, *ids.last().unwrap(), 6);
    drop(st);
    let (sc2, _st2, rep) = reopen(&p, &chain);
    assert_eq!((rep.loaded, rep.skipped, rep.truncated_bytes), (6, 0, 0));
    assert_eq!(sc2.len(), sc.len());
    assert_eq!(sc2.tip(), sc.tip());
    // y se puede seguir: la plantilla sobre la punta recuperada es válida
    let parent = *ids.last().unwrap();
    let ts = chain.header(&parent).unwrap().timestamp + TARGET_BLOCK_TIME;
    let t = sc2.template(&chain, parent, addr(9), ts).unwrap();
    assert_eq!(t.meta().unwrap().prev_share, sc.tip().unwrap());
    let _ = fs::remove_file(&p);
}

#[test]
fn a_torn_tail_is_cut_and_the_file_keeps_working() {
    let (chain, ids) = chain_with(2, b"s");
    let parent = *ids.last().unwrap();
    let p = path("torn");
    let (_sc, st) = fill(&p, &chain, parent, 5);
    drop(st);
    let len = fs::metadata(&p).unwrap().len();
    OpenOptions::new().write(true).open(&p).unwrap().set_len(len - 7).unwrap(); // corte a mitad del último
    let (mut sc2, mut st2, rep) = reopen(&p, &chain);
    assert_eq!(rep.loaded, 4);
    assert!(rep.truncated_bytes > 0 && rep.reason.is_some());
    // el archivo quedó consistente: se añade y se vuelve a leer sin recortes
    let ts = chain.header(&parent).unwrap().timestamp + TARGET_BLOCK_TIME;
    let t = sc2.template(&chain, parent, addr(1), ts).unwrap();
    assert!(matches!(sc2.add(t.clone(), &chain, NOW, &mut SkipPow), Ok(AddShare::Added { .. })));
    st2.append(&t).unwrap();
    drop(st2);
    let (sc3, _s3, rep3) = reopen(&p, &chain);
    assert_eq!((rep3.loaded, rep3.truncated_bytes), (5, 0));
    assert_eq!(sc3.tip(), sc2.tip());
    let _ = fs::remove_file(&p);
}

#[test]
fn a_corrupted_record_cuts_the_file_there() {
    let (chain, ids) = chain_with(2, b"s");
    let p = path("corrupt");
    let (_sc, st) = fill(&p, &chain, *ids.last().unwrap(), 6);
    drop(st);
    let mut bytes = fs::read(&p).unwrap();
    let mid = 40 + (bytes.len() - 40) / 2;
    bytes[mid] ^= 0xff;
    fs::write(&p, &bytes).unwrap();
    let (sc2, _s, rep) = reopen(&p, &chain);
    assert!(rep.loaded < 6 && rep.loaded >= 1, "{rep:?}");
    assert_eq!(sc2.len(), rep.loaded);
    assert_eq!(rep.reason.as_deref(), Some("checksum incorrecto"));
    let _ = fs::remove_file(&p);
}

#[test]
fn another_network_or_garbage_is_refused() {
    let (chain, ids) = chain_with(2, b"red-a");
    let (other, _) = chain_with(2, b"red-b");
    let p = path("wrongnet");
    let (_sc, st) = fill(&p, &chain, *ids.last().unwrap(), 3);
    drop(st);
    let mut sc = ShareChain::new(PARAMS);
    assert!(matches!(ShareStore::open(&p, &other, &mut sc, NOW, &mut SkipPow), Err(ShareStoreError::WrongNetwork)));
    let g = path("garbage");
    fs::write(&g, vec![7u8; 100]).unwrap();
    assert!(matches!(ShareStore::open(&g, &chain, &mut sc, NOW, &mut SkipPow), Err(ShareStoreError::BadHeader)));
    let _ = fs::remove_file(&p);
    let _ = fs::remove_file(&g);
}

#[test]
fn shares_whose_block_is_gone_are_skipped_not_fatal() {
    let (chain, ids) = chain_with(2, b"s");
    let p = path("gone");
    let (_sc, st) = fill(&p, &chain, *ids.last().unwrap(), 4);
    drop(st);
    // blocks.db perdió sus últimos bloques: la cadena solo llega al génesis
    let (short, _) = chain_with(0, b"s");
    let mut sc = ShareChain::new(PARAMS);
    let (_st, rep) = ShareStore::open(&p, &short, &mut sc, NOW, &mut SkipPow).unwrap();
    assert_eq!((rep.loaded, rep.skipped), (0, 4));
    assert!(sc.is_empty());
    let _ = fs::remove_file(&p);
}

#[test]
fn compaction_drops_what_the_sharechain_pruned() {
    let (chain, ids) = chain_with(2, b"s");
    let parent = *ids.last().unwrap();
    let p = path("compact");
    let (sc, mut st) = fill(&p, &chain, parent, 700);
    assert_eq!(st.records(), 700);
    assert!(sc.len() < 80, "len={}", sc.len());
    assert!(st.needs_compaction(sc.len()));
    let before = fs::metadata(&p).unwrap().len();
    st.compact(&sc).unwrap();
    assert_eq!(st.records(), sc.len());
    assert!(fs::metadata(&p).unwrap().len() < before / 4);
    // lo conservado se recarga entero y con la misma punta (el primero entra como base)
    drop(st);
    let (sc2, _s, rep) = reopen(&p, &chain);
    assert_eq!((rep.loaded, rep.skipped), (sc.len(), 0));
    assert_eq!(sc2.tip(), sc.tip());
    assert_eq!(sc2.len(), sc.len());
    let _ = fs::remove_file(&p);
}

#[test]
fn opening_a_bloated_file_compacts_it_and_appends_still_work() {
    let (chain, ids) = chain_with(2, b"s");
    let parent = *ids.last().unwrap();
    let p = path("bloated");
    let (_sc, st) = fill(&p, &chain, parent, 700);
    drop(st);
    let (mut sc2, mut st2, rep) = reopen(&p, &chain);
    assert!(rep.compacted, "{rep:?}");
    assert!(st2.records() < 100);
    let ts = chain.header(&parent).unwrap().timestamp + TARGET_BLOCK_TIME;
    let t = sc2.template(&chain, parent, addr(2), ts).unwrap();
    assert!(matches!(sc2.add(t.clone(), &chain, NOW, &mut SkipPow), Ok(AddShare::Added { .. })));
    st2.append(&t).unwrap();
    drop(st2);
    let (sc3, _s, rep3) = reopen(&p, &chain);
    assert_eq!(rep3.skipped, 0);
    assert_eq!(sc3.tip(), sc2.tip());
    // un archivo con basura al final tras compactar sigue siendo recortable
    OpenOptions::new().append(true).open(&p).unwrap().write_all(&[1, 2, 3]).unwrap();
    let (_s4, _t4, rep4) = reopen(&p, &chain);
    assert_eq!(rep4.truncated_bytes, 3);
    let _ = fs::remove_file(&p);
}
