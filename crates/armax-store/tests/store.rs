use std::fs;
use std::path::PathBuf;

use armax_chain::block::genesis_block;
use armax_chain::{AddOutcome, Address, DamperParams, SkipPow, COIN};
use armax_keys::address::address_from_public_key;
use armax_keys::ed25519::Keypair;
use armax_keys::tx::{OutPoint, Transaction, TxOut};
use armax_ledger::{FullBlock, Ledger, LedgerError};
use armax_store::{Store, StoreError};

const T0: u64 = 1_800_000_000;
const NOW: u64 = T0 + 100_000_000;
const STEP: u64 = 300;

struct TmpFile(PathBuf);
impl TmpFile {
    fn new(name: &str) -> TmpFile {
        let p = std::env::temp_dir().join(format!("armax-store-{}-{}.db", std::process::id(), name));
        let _ = fs::remove_file(&p);
        TmpFile(p)
    }
}
impl Drop for TmpFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn key(n: u8) -> (Keypair, Address) {
    let kp = Keypair::from_seed([n; 32]);
    let a = address_from_public_key(&kp.public_key());
    (kp, a)
}
fn ledger() -> Ledger {
    Ledger::new(DamperParams::MAINNET, genesis_block(T0, b"store"), 2).unwrap()
}
fn block_on(l: &Ledger, parent: &[u8; 32], miner: Address, txs: Vec<Transaction>, fees: u64, tag: u8) -> FullBlock {
    let h = l.chain().header(parent).unwrap().height + 1;
    let leaves = txs.iter().map(|t| t.full_id()).collect();
    let block = l
        .chain()
        .build_template_full(parent, &[(miner, 1_000_000)], T0 + h * STEP, vec![tag], fees, leaves)
        .unwrap();
    FullBlock { block, txs }
}
fn fingerprint(l: &Ledger) -> ([u8; 32], u64, usize, u128, (u128, i128)) {
    (l.tip_id(), l.tip_height(), l.utxos().len(), l.utxos().total_amount(), l.supply())
}

/// Construye en `path` una historia con transacción, rama lateral y reorg; devuelve la huella final
/// y el número de bloques escritos.
fn build_history(path: &PathBuf) -> (([u8; 32], u64, usize, u128, (u128, i128)), usize) {
    let (ka, a) = key(1);
    let (_, b) = key(2);
    let (_, c) = key(3);
    let mut l = ledger();
    let (mut st, rep) = Store::open(path, &mut l, NOW, &mut SkipPow).unwrap();
    assert_eq!(rep.blocks_loaded, 0);
    let mut n = 0;
    let mut ids = vec![];
    for _ in 0..101 {
        let tip = l.tip_id();
        let fb = block_on(&l, &tip, a, vec![], 0, 0);
        ids.push(fb.id());
        st.add_block(&mut l, fb, NOW, &mut SkipPow).unwrap();
        n += 1;
    }
    let fork = l.tip_id();
    let cb = l.chain().coinbase_of(&ids[0]).unwrap().id();
    let pay = Transaction::build_signed(
        &[(OutPoint { txid: cb, index: 0 }, &ka)],
        vec![TxOut { address: b, amount: 20 * COIN }, TxOut { address: a, amount: 5 * COIN - 700 }],
        &l.chain_id(),
    )
    .unwrap();
    let x1 = block_on(&l, &fork, a, vec![pay], 700, 10);
    st.add_block(&mut l, x1, NOW, &mut SkipPow).unwrap();
    n += 1;
    // rama lateral que gana (2 bloques) y luego el bloque ya conocido
    let y1 = block_on(&l, &fork, c, vec![], 0, 20);
    let y1id = y1.id();
    st.add_block(&mut l, y1.clone(), NOW, &mut SkipPow).unwrap();
    let y2 = block_on(&l, &y1id, c, vec![], 0, 21);
    st.add_block(&mut l, y2, NOW, &mut SkipPow).unwrap();
    n += 2;
    assert_eq!(st.add_block(&mut l, y1, NOW, &mut SkipPow).unwrap(), AddOutcome::AlreadyKnown);
    (fingerprint(&l), n)
}

#[test]
fn reopening_rebuilds_the_exact_same_state() {
    let f = TmpFile::new("roundtrip");
    let (fp, n) = build_history(&f.0);
    let mut l = ledger();
    let (_, rep) = Store::open(&f.0, &mut l, NOW, &mut SkipPow).unwrap();
    assert_eq!(rep.blocks_loaded, n);
    assert_eq!(rep.truncated_bytes, 0);
    assert_eq!(fingerprint(&l), fp);
}

#[test]
fn torn_tail_is_cut_and_the_file_stays_usable() {
    let f = TmpFile::new("torn");
    let (_, n) = build_history(&f.0);
    let len = fs::metadata(&f.0).unwrap().len();
    // simula un corte a mitad del último registro
    let file = fs::OpenOptions::new().write(true).open(&f.0).unwrap();
    file.set_len(len - 5).unwrap();
    drop(file);

    let mut l = ledger();
    let (mut st, rep) = Store::open(&f.0, &mut l, NOW, &mut SkipPow).unwrap();
    assert_eq!(rep.blocks_loaded, n - 1);
    assert!(rep.truncated_bytes > 0 && rep.reason.is_some());
    // sigue aceptando bloques y queda consistente al reabrir
    let (_, a) = key(1);
    let tip = l.tip_id();
    let fb = block_on(&l, &tip, a, vec![], 0, 77);
    st.add_block(&mut l, fb, NOW, &mut SkipPow).unwrap();
    let fp = fingerprint(&l);
    drop(st);
    let mut l2 = ledger();
    let (_, rep2) = Store::open(&f.0, &mut l2, NOW, &mut SkipPow).unwrap();
    assert_eq!(rep2.truncated_bytes, 0);
    assert_eq!(fingerprint(&l2), fp);
}

#[test]
fn corruption_in_the_middle_keeps_only_the_good_prefix() {
    let f = TmpFile::new("corrupt");
    build_history(&f.0);
    let mut data = fs::read(&f.0).unwrap();
    let mid = 40 + (data.len() - 40) / 2;
    data[mid] ^= 0xFF;
    fs::write(&f.0, &data).unwrap();
    let mut l = ledger();
    let (_, rep) = Store::open(&f.0, &mut l, NOW, &mut SkipPow).unwrap();
    assert!(rep.blocks_loaded > 0 && rep.blocks_loaded < 105);
    assert_eq!(rep.reason.as_deref().is_some(), true);
    // el libro mayor es consistente con lo cargado
    let (u, e) = l.supply();
    assert_eq!(u as i128, e);
    assert_eq!(l.tip_height() as usize, rep.blocks_loaded);
}

#[test]
fn file_of_another_network_or_garbage_is_refused() {
    let f = TmpFile::new("net");
    build_history(&f.0);
    let mut other = Ledger::new(DamperParams::MAINNET, genesis_block(T0, b"otra red"), 2).unwrap();
    assert!(matches!(Store::open(&f.0, &mut other, NOW, &mut SkipPow), Err(StoreError::WrongNetwork)));

    fs::write(&f.0, b"esto no es una base de datos de armax, ni de cerca").unwrap();
    let mut l = ledger();
    assert!(matches!(Store::open(&f.0, &mut l, NOW, &mut SkipPow), Err(StoreError::BadHeader)));
}

#[test]
fn rejected_blocks_are_not_written() {
    let f = TmpFile::new("rejected");
    let (ka, a) = key(1);
    let (_, b) = key(2);
    let mut l = ledger();
    let (mut st, _) = Store::open(&f.0, &mut l, NOW, &mut SkipPow).unwrap();
    let mut first = None;
    for _ in 0..101 {
        let tip = l.tip_id();
        let fb = block_on(&l, &tip, a, vec![], 0, 0);
        first.get_or_insert(fb.id());
        st.add_block(&mut l, fb, NOW, &mut SkipPow).unwrap();
    }
    let size = fs::metadata(&f.0).unwrap().len();
    let op = OutPoint { txid: l.chain().coinbase_of(&first.unwrap()).unwrap().id(), index: 0 };
    let t1 = Transaction::build_signed(&[(op, &ka)], vec![TxOut { address: b, amount: 25 * COIN }], &l.chain_id()).unwrap();
    let t2 = Transaction::build_signed(&[(op, &ka)], vec![TxOut { address: a, amount: 25 * COIN }], &l.chain_id()).unwrap();
    let tip = l.tip_id();
    let bad = block_on(&l, &tip, a, vec![t1, t2], 0, 1);
    assert!(matches!(st.add_block(&mut l, bad, NOW, &mut SkipPow), Err(StoreError::Ledger(LedgerError::Invalid { .. }))));
    assert_eq!(fs::metadata(&f.0).unwrap().len(), size);
}

#[test]
fn full_block_codec_roundtrips_and_is_strict() {
    let (ka, a) = key(1);
    let (_, b) = key(2);
    let mut l = ledger();
    let mut first = None;
    for _ in 0..101 {
        let tip = l.tip_id();
        let fb = block_on(&l, &tip, a, vec![], 0, 0);
        first.get_or_insert(fb.id());
        l.add_block(fb, NOW, &mut SkipPow).unwrap();
    }
    let op = OutPoint { txid: l.chain().coinbase_of(&first.unwrap()).unwrap().id(), index: 0 };
    let t = Transaction::build_signed(&[(op, &ka)], vec![TxOut { address: b, amount: 25 * COIN - 9 }], &l.chain_id()).unwrap();
    let tip = l.tip_id();
    let fb = block_on(&l, &tip, a, vec![t], 9, 5);
    let bytes = fb.to_bytes();
    assert_eq!(FullBlock::from_bytes(&bytes), Ok(fb.clone()));
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(FullBlock::from_bytes(&longer).is_err());
    for cut in (0..bytes.len()).step_by(7) {
        assert!(FullBlock::from_bytes(&bytes[..cut]).is_err(), "cut={cut}");
    }
}
