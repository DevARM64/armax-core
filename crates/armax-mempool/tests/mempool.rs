use armax_chain::block::genesis_block;
use armax_chain::{Address, DamperParams, SkipPow, COIN};
use armax_keys::address::address_from_public_key;
use armax_keys::ed25519::Keypair;
use armax_keys::tx::{OutPoint, Transaction, TxOut};
use armax_ledger::{FullBlock, Ledger};
use armax_mempool::{AddResult, Mempool, MempoolConfig, MempoolError};

const T0: u64 = 1_800_000_000;
const NOW: u64 = T0 + 100_000_000;
const STEP: u64 = 300;
const SUB: u64 = 25 * COIN;

fn key(n: u8) -> (Keypair, Address) {
    let kp = Keypair::from_seed([n; 32]);
    let a = address_from_public_key(&kp.public_key());
    (kp, a)
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

/// Ledger con 110 bloques minados por `a`; devuelve los ids (ids[i] = bloque de altura i+1).
fn setup() -> (Ledger, Vec<[u8; 32]>) {
    let (_, a) = key(1);
    let mut l = Ledger::new(DamperParams::MAINNET, genesis_block(T0, b"mempool"), 2).unwrap();
    let mut ids = vec![];
    for _ in 0..110 {
        let tip = l.tip_id();
        let fb = block_on(&l, &tip, a, vec![], 0, 0);
        ids.push(fb.id());
        l.add_block(fb, NOW, &mut SkipPow).unwrap();
    }
    (l, ids)
}

fn op(l: &Ledger, id: &[u8; 32]) -> OutPoint {
    OutPoint { txid: l.chain().coinbase_of(id).unwrap().id(), index: 0 }
}

fn spend(l: &Ledger, from: &[u8; 32], signer: &Keypair, to: Address, fee: u64) -> Transaction {
    Transaction::build_signed(&[(op(l, from), signer)], vec![TxOut { address: to, amount: SUB - fee }], &l.chain_id()).unwrap()
}

#[test]
fn admission_and_rejections() {
    let (l, ids) = setup();
    let (ka, _) = key(1);
    let (kb, b) = key(2);
    let mut pool = Mempool::new(MempoolConfig::default());

    let t = spend(&l, &ids[0], &ka, b, 10_000);
    let txid = t.txid();
    assert_eq!(pool.add(t.clone(), &l), Ok(AddResult::Added));
    assert_eq!(pool.add(t, &l), Ok(AddResult::AlreadyKnown));
    assert_eq!(pool.fee_of(&txid), Some(10_000));
    assert_eq!(pool.len(), 1);

    // entrada inexistente
    let ghost = Transaction::build_signed(
        &[(OutPoint { txid: [9; 32], index: 0 }, &ka)],
        vec![TxOut { address: b, amount: 1 }],
        &l.chain_id(),
    )
    .unwrap();
    assert_eq!(pool.add(ghost, &l), Err(MempoolError::MissingInput(0)));
    // firma de quien no es el dueño
    let stolen = spend(&l, &ids[1], &kb, b, 10_000);
    assert_eq!(pool.add(stolen, &l), Err(MempoolError::WrongOwner(0)));
    // coinbase inmaduro (altura 110, próximo bloque 111 < 110 + 100)
    let young = spend(&l, &ids[109], &ka, b, 10_000);
    assert_eq!(pool.add(young, &l), Err(MempoolError::Immature(0)));
    // salidas > entradas
    let rich = Transaction::build_signed(&[(op(&l, &ids[2]), &ka)], vec![TxOut { address: b, amount: SUB + 1 }], &l.chain_id()).unwrap();
    assert_eq!(pool.add(rich, &l), Err(MempoolError::OutputsExceedInputs));
    // comisión por debajo del mínimo
    let cheap = spend(&l, &ids[3], &ka, b, 0);
    assert!(matches!(pool.add(cheap, &l), Err(MempoolError::FeeTooLow { fee: 0, .. })));
    // firma corrupta: el estado es válido, así que falla en el último paso
    let mut forged = spend(&l, &ids[4], &ka, b, 10_000);
    forged.inputs[0].signature[0] ^= 1;
    assert!(matches!(pool.add(forged, &l), Err(MempoolError::Invalid(_))));
    assert_eq!(pool.len(), 1);
}

#[test]
fn replacement_needs_a_clearly_higher_fee() {
    let (l, ids) = setup();
    let (ka, a) = key(1);
    let (_, b) = key(2);
    let mut pool = Mempool::new(MempoolConfig::default());
    let t1 = spend(&l, &ids[0], &ka, b, 10_000);
    let id1 = t1.txid();
    pool.add(t1, &l).unwrap();

    // misma comisión, o mayor pero sin cubrir el mínimo adicional: rechazada
    let same = spend(&l, &ids[0], &ka, a, 10_000);
    assert!(matches!(pool.add(same, &l), Err(MempoolError::ReplacementRejected { .. })));
    let barely = spend(&l, &ids[0], &ka, a, 10_050);
    assert!(matches!(pool.add(barely, &l), Err(MempoolError::ReplacementRejected { .. })));
    assert!(pool.contains(&id1));

    let better = spend(&l, &ids[0], &ka, a, 20_000);
    let id2 = better.txid();
    assert_eq!(pool.add(better, &l), Ok(AddResult::AddedDisplacing(vec![id1])));
    assert!(!pool.contains(&id1) && pool.contains(&id2));
    assert_eq!(pool.len(), 1);
}

#[test]
fn full_pool_evicts_the_lowest_rate_only_for_a_better_payer() {
    let (l, ids) = setup();
    let (ka, _) = key(1);
    let (_, b) = key(2);
    let mut pool = Mempool::new(MempoolConfig { max_txs: 3, ..MempoolConfig::default() });
    let t10 = spend(&l, &ids[0], &ka, b, 10_000);
    let t20 = spend(&l, &ids[1], &ka, b, 20_000);
    let t30 = spend(&l, &ids[2], &ka, b, 30_000);
    let (id10, id20, id30) = (t10.txid(), t20.txid(), t30.txid());
    for t in [t10, t20, t30] {
        pool.add(t, &l).unwrap();
    }
    // paga menos o igual que la peor: rechazada, el pool queda intacto
    let t5 = spend(&l, &ids[3], &ka, b, 5_000);
    assert_eq!(pool.add(t5, &l), Err(MempoolError::PoolFull));
    let t10b = spend(&l, &ids[3], &ka, b, 10_000);
    assert_eq!(pool.add(t10b, &l), Err(MempoolError::PoolFull));
    assert_eq!(pool.len(), 3);
    // paga más: expulsa a la peor
    let t40 = spend(&l, &ids[3], &ka, b, 40_000);
    let id40 = t40.txid();
    assert_eq!(pool.add(t40, &l), Ok(AddResult::AddedDisplacing(vec![id10])));
    assert!(!pool.contains(&id10) && pool.contains(&id20) && pool.contains(&id30) && pool.contains(&id40));
}

#[test]
fn byte_limit_is_enforced() {
    let (l, ids) = setup();
    let (ka, _) = key(1);
    let (_, b) = key(2);
    let one = spend(&l, &ids[0], &ka, b, 10_000).to_bytes().len();
    let mut pool = Mempool::new(MempoolConfig { max_bytes: one * 2 + 1, ..MempoolConfig::default() });
    pool.add(spend(&l, &ids[0], &ka, b, 10_000), &l).unwrap();
    pool.add(spend(&l, &ids[1], &ka, b, 20_000), &l).unwrap();
    assert_eq!(pool.add(spend(&l, &ids[2], &ka, b, 5_000), &l), Err(MempoolError::PoolFull));
    assert!(pool.total_bytes() <= one * 2 + 1);
    pool.add(spend(&l, &ids[2], &ka, b, 30_000), &l).unwrap();
    assert_eq!(pool.len(), 2);
    assert!(pool.total_bytes() <= one * 2 + 1);
}

#[test]
fn candidates_by_rate_feed_a_block_and_the_pool_empties() {
    let (mut l, ids) = setup();
    let (ka, a) = key(1);
    let (_, b) = key(2);
    let mut pool = Mempool::new(MempoolConfig::default());
    let fees = [15_000u64, 40_000, 25_000];
    for (i, f) in fees.iter().enumerate() {
        pool.add(spend(&l, &ids[i], &ka, b, *f), &l).unwrap();
    }
    let cands = pool.candidates();
    let order: Vec<u64> = cands.iter().map(|t| pool.fee_of(&t.txid()).unwrap()).collect();
    assert_eq!(order, vec![40_000, 25_000, 15_000]);

    let fb = l.build_template(&[(a, 1_000_000)], T0 + 111 * STEP, vec![], &cands).unwrap();
    assert_eq!(fb.txs.len(), 3);
    assert_eq!(fb.block.coinbase.fees, 80_000);
    l.add_block(fb, NOW, &mut SkipPow).unwrap();
    pool.on_chain_update(&mut l);
    assert!(pool.is_empty());
    assert_eq!(pool.total_bytes(), 0);
    assert_eq!(l.balance_of(&b), (3 * SUB - 80_000) as u128);
}

#[test]
fn a_confirmed_conflict_drops_the_pool_entry() {
    let (mut l, ids) = setup();
    let (ka, a) = key(1);
    let (_, b) = key(2);
    let (_, c) = key(3);
    let mut pool = Mempool::new(MempoolConfig::default());
    let mine = spend(&l, &ids[0], &ka, b, 10_000);
    pool.add(mine, &l).unwrap();
    // otra versión (no vista por este nodo) se confirma en un bloque
    let other = spend(&l, &ids[0], &ka, c, 12_000);
    let tip = l.tip_id();
    let fb = block_on(&l, &tip, a, vec![other], 12_000, 1);
    l.add_block(fb, NOW, &mut SkipPow).unwrap();
    pool.on_chain_update(&mut l);
    assert!(pool.is_empty());
}

#[test]
fn reorg_returns_transactions_to_the_pool_and_confirms_them_again() {
    let (mut l, ids) = setup();
    let (ka, a) = key(1);
    let (_, b) = key(2);
    let (_, c) = key(3);
    let mut pool = Mempool::new(MempoolConfig::default());
    let fork = l.tip_id();
    let t = spend(&l, &ids[0], &ka, b, 10_000);
    let txid = t.txid();

    // X1 confirma t
    let x1 = block_on(&l, &fork, a, vec![t], 10_000, 10);
    let x1id = x1.id();
    l.add_block(x1, NOW, &mut SkipPow).unwrap();
    pool.on_chain_update(&mut l);
    assert!(pool.is_empty());

    // Y1, Y2 (sin t) ganan: t vuelve al pool
    let y1 = block_on(&l, &fork, c, vec![], 0, 20);
    let y1id = y1.id();
    l.add_block(y1, NOW, &mut SkipPow).unwrap();
    let y2 = block_on(&l, &y1id, c, vec![], 0, 21);
    l.add_block(y2, NOW, &mut SkipPow).unwrap();
    pool.on_chain_update(&mut l);
    assert!(pool.contains(&txid), "la transacción de un bloque deshecho vuelve al pool");
    assert_eq!(l.balance_of(&b), 0);

    // X vuelve a ganar con 2 bloques más: t queda confirmada y sale del pool
    let mut parent = x1id;
    for tag in 11..13u8 {
        let fb = block_on(&l, &parent, a, vec![], 0, tag);
        parent = fb.id();
        l.add_block(fb, NOW, &mut SkipPow).unwrap();
    }
    pool.on_chain_update(&mut l);
    assert!(pool.is_empty());
    assert_eq!(l.balance_of(&b), (SUB - 10_000) as u128);
    let (u, e) = l.supply();
    assert_eq!(u as i128, e);
}
