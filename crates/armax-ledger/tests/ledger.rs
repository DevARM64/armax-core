use armax_chain::block::genesis_block;
use armax_chain::{AddOutcome, Address, DamperParams, SkipPow, COIN};
use armax_keys::address::address_from_public_key;
use armax_keys::ed25519::Keypair;
use armax_keys::tx::{OutPoint, Transaction, TxIn, TxOut};
use armax_ledger::{FullBlock, InvalidReason, Ledger, LedgerError, MAX_BLOCK_INPUTS};
use armax_keys::utxo::UtxoError;

const T0: u64 = 1_800_000_000;
const NOW: u64 = T0 + 100_000_000;
const STEP: u64 = 300;

fn key(n: u8) -> (Keypair, Address) {
    let kp = Keypair::from_seed([n; 32]);
    let a = address_from_public_key(&kp.public_key());
    (kp, a)
}

fn new_ledger() -> Ledger {
    Ledger::new(DamperParams::MAINNET, genesis_block(T0, b"ledger"), 2).unwrap()
}

/// Bloque sobre `parent` con las transacciones dadas y comisiones declaradas.
fn block_on(l: &Ledger, parent: &[u8; 32], miner: Address, txs: Vec<Transaction>, fees: u64, tag: u8) -> FullBlock {
    let h = l.chain().header(parent).unwrap().height + 1;
    let leaves = txs.iter().map(|t| t.full_id()).collect();
    let block = l
        .chain()
        .build_template_full(parent, &[(miner, 1_000_000)], T0 + h * STEP, vec![tag], fees, leaves)
        .unwrap();
    FullBlock { block, txs }
}

fn push(l: &mut Ledger, fb: FullBlock) -> Result<AddOutcome, LedgerError> {
    l.add_block(fb, NOW, &mut SkipPow)
}

/// Mina `n` bloques vacíos a `miner` sobre la punta; devuelve los ids.
fn mine_empty(l: &mut Ledger, miner: Address, n: usize) -> Vec<[u8; 32]> {
    let mut ids = vec![];
    for _ in 0..n {
        let parent = l.tip_id();
        let fb = block_on(l, &parent, miner, vec![], 0, 0);
        ids.push(fb.id());
        push(l, fb).unwrap();
    }
    ids
}

fn coinbase_point(l: &Ledger, block: &[u8; 32]) -> OutPoint {
    OutPoint { txid: l.chain().coinbase_of(block).unwrap().id(), index: 0 }
}

fn assert_supply(l: &Ledger) {
    let (utxo, expected) = l.supply();
    assert_eq!(utxo as i128, expected);
}

#[test]
fn fees_flow_to_the_coinbase_and_supply_balances() {
    let mut l = new_ledger();
    let (ka, a) = key(1);
    let (_, b) = key(2);
    let ids = mine_empty(&mut l, a, 101);
    assert_eq!(l.balance_of(&a), 101 * 25 * COIN as u128);

    let spend = Transaction::build_signed(
        &[(coinbase_point(&l, &ids[0]), &ka)],
        vec![TxOut { address: b, amount: 10 * COIN }, TxOut { address: a, amount: 25 * COIN - 10 * COIN - 10_000 }],
        &l.chain_id(),
    )
    .unwrap();
    let fb = l.build_template(&[(a, 1_000_000)], T0 + 102 * STEP, vec![], &[spend]).unwrap();
    assert_eq!(fb.txs.len(), 1);
    assert_eq!(fb.block.coinbase.fees, 10_000);
    push(&mut l, fb).unwrap();

    assert_eq!(l.balance_of(&b), 10 * COIN as u128);
    // a: 102 coinbases (la última incluye la comisión) menos lo gastado (10 ARM) menos la comisión pagada y devuelta
    assert_eq!(l.balance_of(&a), (102 * 25 * COIN - 10 * COIN) as u128);
    assert_supply(&l);
}

#[test]
fn double_spend_inside_a_block_is_rejected_and_state_is_untouched() {
    let mut l = new_ledger();
    let (ka, a) = key(1);
    let (_, b) = key(2);
    let ids = mine_empty(&mut l, a, 101);
    let op = coinbase_point(&l, &ids[0]);
    let t1 = Transaction::build_signed(&[(op, &ka)], vec![TxOut { address: b, amount: 25 * COIN }], &l.chain_id()).unwrap();
    let t2 = Transaction::build_signed(&[(op, &ka)], vec![TxOut { address: a, amount: 25 * COIN }], &l.chain_id()).unwrap();
    let tip = l.tip_id();
    let before = l.utxos().total_amount();
    let bad = block_on(&l, &tip, a, vec![t1, t2], 0, 1);
    let bad_id = bad.id();
    let err = push(&mut l, bad).unwrap_err();
    assert!(matches!(err, LedgerError::Invalid { block, reason: InvalidReason::Tx { index: 1, .. } } if block == bad_id));
    assert_eq!(l.tip_id(), tip);
    assert!(l.chain().is_invalid(&bad_id));
    assert_eq!(l.utxos().total_amount(), before);
    assert_eq!(l.balance_of(&b), 0);
    assert_supply(&l);
}

#[test]
fn wrong_declared_fees_are_rejected() {
    let mut l = new_ledger();
    let (ka, a) = key(1);
    let (_, b) = key(2);
    let ids = mine_empty(&mut l, a, 101);
    let t = Transaction::build_signed(
        &[(coinbase_point(&l, &ids[0]), &ka)],
        vec![TxOut { address: b, amount: 25 * COIN - 500 }],
        &l.chain_id(),
    )
    .unwrap();
    let tip = l.tip_id();
    let bad = block_on(&l, &tip, a, vec![t], 499, 1);
    let err = push(&mut l, bad).unwrap_err();
    assert!(matches!(err, LedgerError::Invalid { reason: InvalidReason::FeesMismatch { declared: 499, computed: 500 }, .. }));
    assert_eq!(l.tip_id(), tip);
    assert_supply(&l);
}

#[test]
fn immature_coinbase_cannot_be_spent() {
    let mut l = new_ledger();
    let (ka, a) = key(1);
    let (_, b) = key(2);
    let ids = mine_empty(&mut l, a, 50);
    let t = Transaction::build_signed(
        &[(coinbase_point(&l, &ids[0]), &ka)],
        vec![TxOut { address: b, amount: 25 * COIN }],
        &l.chain_id(),
    )
    .unwrap();
    let tip = l.tip_id();
    let bad = block_on(&l, &tip, a, vec![t], 0, 1);
    let err = push(&mut l, bad).unwrap_err();
    assert!(matches!(err, LedgerError::Invalid { reason: InvalidReason::Tx { error: UtxoError::ImmatureCoinbase(_), .. }, .. }));
}

#[test]
fn reorg_reverts_and_reapplies_state() {
    let mut l = new_ledger();
    let (ka, a) = key(1);
    let (_, b) = key(2);
    let (_, c) = key(3);
    let ids = mine_empty(&mut l, a, 101);
    let fork = l.tip_id();
    let op = coinbase_point(&l, &ids[0]);
    let pay_b = Transaction::build_signed(&[(op, &ka)], vec![TxOut { address: b, amount: 25 * COIN }], &l.chain_id()).unwrap();

    // rama X: paga a b
    let x1 = block_on(&l, &fork, a, vec![pay_b], 0, 10);
    let x1id = x1.id();
    assert_eq!(push(&mut l, x1).unwrap(), AddOutcome::Extended);
    assert_eq!(l.balance_of(&b), 25 * COIN as u128);

    // rama Y: dos bloques sin la transacción (el segundo la supera en trabajo)
    let y1 = block_on(&l, &fork, c, vec![], 0, 20);
    let y1id = y1.id();
    push(&mut l, y1).unwrap();
    assert_eq!(l.tip_id(), x1id, "empate: se queda la primera vista");
    assert_eq!(l.balance_of(&c), 0, "rama lateral sin ejecutar");
    let y2 = block_on(&l, &y1id, c, vec![], 0, 21);
    push(&mut l, y2).unwrap();
    assert_eq!(l.balance_of(&b), 0);
    assert_eq!(l.balance_of(&c), 2 * 25 * COIN as u128);
    assert_eq!(l.balance_of(&a), 101 * 25 * COIN as u128);
    assert_supply(&l);

    // X vuelve a ganar con dos bloques más
    let mut parent = x1id;
    for t in 11..13u8 {
        let fb = block_on(&l, &parent, a, vec![], 0, t);
        parent = fb.id();
        push(&mut l, fb).unwrap();
    }
    assert_eq!(l.tip_id(), parent);
    assert_eq!(l.balance_of(&b), 25 * COIN as u128);
    assert_eq!(l.balance_of(&c), 0);
    assert_supply(&l);
}

#[test]
fn winning_branch_with_an_invalid_block_rolls_back() {
    let mut l = new_ledger();
    let (ka, a) = key(1);
    let (_, b) = key(2);
    let (_, c) = key(3);
    let ids = mine_empty(&mut l, a, 101);
    let fork = l.tip_id();
    let op = coinbase_point(&l, &ids[0]);
    let pay_b = Transaction::build_signed(&[(op, &ka)], vec![TxOut { address: b, amount: 25 * COIN }], &l.chain_id()).unwrap();
    let x1 = block_on(&l, &fork, a, vec![pay_b], 0, 10);
    let x1id = x1.id();
    push(&mut l, x1).unwrap();
    let snapshot = (l.utxos().len(), l.utxos().total_amount());

    // rama Y: y1 válido, y2 gasta algo inexistente
    let y1 = block_on(&l, &fork, c, vec![], 0, 20);
    let y1id = y1.id();
    push(&mut l, y1).unwrap();
    let ghost = Transaction::build_signed(
        &[(OutPoint { txid: [9; 32], index: 0 }, &ka)],
        vec![TxOut { address: c, amount: 1 }],
        &l.chain_id(),
    )
    .unwrap();
    let y2 = block_on(&l, &y1id, c, vec![ghost], 0, 21);
    let y2id = y2.id();
    let err = push(&mut l, y2).unwrap_err();
    assert!(matches!(err, LedgerError::Invalid { block, reason: InvalidReason::Tx { error: UtxoError::MissingInput(_), .. } } if block == y2id));
    assert_eq!(l.tip_id(), x1id);
    assert!(l.chain().is_invalid(&y2id));
    assert_eq!((l.utxos().len(), l.utxos().total_amount()), snapshot);
    assert_eq!(l.balance_of(&b), 25 * COIN as u128);
    assert_supply(&l);
}

#[test]
fn tx_leaves_must_match_the_bodies() {
    let mut l = new_ledger();
    let (ka, a) = key(1);
    let (_, b) = key(2);
    let ids = mine_empty(&mut l, a, 101);
    let t = Transaction::build_signed(
        &[(coinbase_point(&l, &ids[0]), &ka)],
        vec![TxOut { address: b, amount: 25 * COIN }],
        &l.chain_id(),
    )
    .unwrap();
    let tip = l.tip_id();
    let mut fb = block_on(&l, &tip, a, vec![t], 0, 1);
    fb.txs.clear();
    assert_eq!(push(&mut l, fb).unwrap_err(), LedgerError::TxLeavesMismatch);
}

#[test]
fn input_cap_is_enforced_before_any_signature_work() {
    let mut l = new_ledger();
    let (_, a) = key(1);
    mine_empty(&mut l, a, 1);
    let n_tx = MAX_BLOCK_INPUTS / 64 + 1; // 32 tx × 64 = 2048 > 2000
    let txs: Vec<Transaction> = (0..n_tx)
        .map(|t| Transaction {
            inputs: (0..64)
                .map(|i| TxIn {
                    prev: OutPoint { txid: [t as u8; 32], index: i },
                    public_key: [0; 32],
                    signature: [0; 64],
                })
                .collect(),
            outputs: vec![TxOut { address: a, amount: 1 }],
        })
        .collect();
    let tip = l.tip_id();
    let fb = block_on(&l, &tip, a, txs, 0, 1);
    assert_eq!(push(&mut l, fb).unwrap_err(), LedgerError::TooManyInputs(n_tx * 64));
}

#[test]
fn known_block_is_ignored() {
    let mut l = new_ledger();
    let (_, a) = key(1);
    let tip = l.tip_id();
    let fb = block_on(&l, &tip, a, vec![], 0, 0);
    push(&mut l, fb.clone()).unwrap();
    assert_eq!(push(&mut l, fb).unwrap(), AddOutcome::AlreadyKnown);
}

#[test]
fn old_undo_data_is_pruned_and_the_memory_stays_bounded() {
    let mut l = new_ledger();
    l.set_undo_depth(5);
    let (_, a) = key(1);
    mine_empty(&mut l, a, 100);
    assert!(l.undo_count() <= 7, "undo_count = {}", l.undo_count());
    assert_supply(&l);
    // una reorganización superficial sigue funcionando
    let tip_before = l.tip_id();
    let parent = l.chain().id_at_height(l.tip_height() - 2).unwrap();
    let (_, b) = key(2);
    let mut p = parent;
    for _ in 0..3 {
        let fb = block_on(&l, &p, b, vec![], 0, 1);
        p = fb.id();
        push(&mut l, fb).unwrap();
    }
    assert_ne!(l.tip_id(), tip_before);
    assert_eq!(l.tip_id(), p);
    assert!(l.balance_of(&b) > 0);
    assert_supply(&l);
}

#[test]
fn a_reorg_deeper_than_the_kept_undo_is_refused_and_the_chain_stays_put() {
    let mut l = new_ledger();
    l.set_undo_depth(5);
    let (_, a) = key(1);
    let (_, b) = key(2);
    let ids = mine_empty(&mut l, a, 20);
    let tip = *ids.last().unwrap();

    // rama desde la altura 10 (10 bloques por detrás de la punta): al superar el trabajo, exige deshacer 10 > 5
    let mut p = ids[9];
    let mut refused = false;
    for _ in 0..11 {
        let fb = block_on(&l, &p, b, vec![], 0, 1);
        p = fb.id();
        match push(&mut l, fb) {
            Ok(_) => {}
            Err(LedgerError::ReorgTooDeep { depth, max }) => {
                assert!(depth > max);
                refused = true;
            }
            Err(e) => panic!("error inesperado: {e:?}"),
        }
    }
    assert!(refused, "la rama profunda debía rechazarse");
    assert_eq!(l.tip_id(), tip, "la cadena principal no debe moverse");
    assert_eq!(l.balance_of(&b), 0);
    assert_supply(&l);
    // y la cadena principal sigue aceptando bloques
    mine_empty(&mut l, a, 3);
    assert_eq!(l.tip_height(), 23);
    assert_supply(&l);
}
