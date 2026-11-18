//! Shares con transacciones: las comisiones entran en el reparto, la sharechain comprueba la
//! estructura y el libro mayor la verdad de las comisiones cuando un share llega a ser bloque.

use armax_chain::block::genesis_block;
use armax_chain::{Address, DamperParams, SkipPow, COIN};
use armax_keys::address::address_from_public_key;
use armax_keys::ed25519::Keypair;
use armax_keys::tx::{OutPoint, Transaction, TxOut};
use armax_ledger::{FullBlock, InvalidReason, Ledger, LedgerError};
use armax_pow::consensus::TARGET_BLOCK_TIME;
use armax_share::{AddShare, Share, ShareChain, ShareError, ShareParams, MAX_SHARE_TXS};

const T0: u64 = 1_800_000_000;
const NOW: u64 = T0 + 100_000_000;
const PARAMS: ShareParams = ShareParams { ratio: 4, window: 16 };
const FEE: u64 = 10_000;

fn key(n: u8) -> (Keypair, Address) {
    let kp = Keypair::from_seed([n; 32]);
    let a = address_from_public_key(&kp.public_key());
    (kp, a)
}

/// Libro mayor con 6 bloques vacíos a `a` (madurez 3) y una transacción válida de `a` a `b` que
/// paga `FEE` de comisión.
fn setup() -> (Ledger, Transaction, Address, Address) {
    let mut l = Ledger::with_maturity(DamperParams::MAINNET, genesis_block(T0, b"txshares"), 2, 3).unwrap();
    let (ka, a) = key(1);
    let (_, b) = key(2);
    let mut first = None;
    for i in 0..6u64 {
        let parent = l.tip_id();
        let block = l
            .chain()
            .build_template_full(&parent, &[(a, 1_000_000)], T0 + (i + 1) * TARGET_BLOCK_TIME, vec![i as u8], 0, vec![])
            .unwrap();
        if i == 0 {
            first = Some(block.coinbase.id());
        }
        l.add_block(FullBlock { block, txs: vec![] }, NOW, &mut SkipPow).unwrap();
    }
    let tx = Transaction::build_signed(
        &[(OutPoint { txid: first.unwrap(), index: 0 }, &ka)],
        vec![TxOut { address: b, amount: 10 * COIN }, TxOut { address: a, amount: 25 * COIN - 10 * COIN - FEE }],
        &l.chain_id(),
    )
    .unwrap();
    (l, tx, a, b)
}

fn ts(l: &Ledger) -> u64 {
    l.chain().header(&l.tip_id()).unwrap().timestamp + TARGET_BLOCK_TIME
}

fn pay_of(s: &Share, a: Address) -> u64 {
    s.coinbase.outputs.iter().filter(|o| o.address == a).map(|o| o.amount).sum()
}

#[test]
fn a_share_with_a_paid_transaction_splits_the_fee_and_confirms_when_it_is_a_block() {
    let (mut l, tx, a, b) = setup();
    let (txs, fees) = l.select_txs_within(&[tx.clone()], MAX_SHARE_TXS, 64 * 1024);
    assert_eq!((txs.len(), fees), (1, FEE));
    let mut sc = ShareChain::new(PARAMS);
    let m1 = Address([7; 32]);
    let m2 = Address([8; 32]);
    // un primer share sin transacciones de m1 y luego uno de m2 con la transacción: la comisión se
    // reparte por partes entre m1 y m2
    let t1 = sc.template(l.chain(), l.tip_id(), m1, ts(&l)).unwrap();
    assert!(matches!(sc.add(t1, l.chain(), NOW, &mut SkipPow), Ok(AddShare::Added { .. })));
    let t2 = sc.template_with(l.chain(), l.tip_id(), m2, ts(&l), txs.clone(), fees).unwrap();
    assert_eq!(t2.coinbase.fees, FEE);
    assert_eq!(t2.header.merkle_root, t2.to_block().header.merkle_root);
    let ppm = |s: &Share, x: Address| s.coinbase.outputs.iter().find(|o| o.address == x).unwrap().share_ppm as u64;
    // la parte de cada uno incluye su fracción de la comisión
    let (p1, p2) = (ppm(&t2, m1), ppm(&t2, m2));
    assert_eq!(p1 + p2, 1_000_000);
    assert!(pay_of(&t2, m1) >= FEE * p1 / 1_000_000 && pay_of(&t2, m2) >= FEE * p2 / 1_000_000);
    assert!(matches!(sc.add(t2.clone(), l.chain(), NOW, &mut SkipPow), Ok(AddShare::Added { is_block: true, .. })));

    // con SkipPow cumple el target del bloque: publicado como bloque, el libro mayor lo acepta y
    // la transacción queda confirmada
    l.add_block(FullBlock { block: t2.to_block(), txs: t2.txs.clone() }, NOW, &mut SkipPow).unwrap();
    assert_eq!(l.balance_of(&b), 10 * COIN as u128);
    let (u, e) = l.supply();
    assert_eq!(u as i128, e);
    let _ = a;
}

#[test]
fn the_merkle_root_must_commit_to_the_transactions() {
    let (l, tx, _, _) = setup();
    let mut sc = ShareChain::new(PARAMS);
    let mut s = sc.template_with(l.chain(), l.tip_id(), Address([7; 32]), ts(&l), vec![tx.clone()], FEE).unwrap();
    s.txs.clear(); // se quita la transacción: la raíz ya no cuadra
    s.coinbase.fees = 0;
    assert!(matches!(sc.add(s, l.chain(), NOW, &mut SkipPow), Err(ShareError::BadMerkleRoot) | Err(ShareError::BadPayout(_))));
    // y cambiar una transacción por otra tampoco pasa
    let mut s = sc.template_with(l.chain(), l.tip_id(), Address([7; 32]), ts(&l), vec![tx.clone()], FEE).unwrap();
    let mut other = tx.clone();
    other.outputs[0].amount += 1;
    s.txs = vec![other];
    assert_eq!(sc.add(s, l.chain(), NOW, &mut SkipPow), Err(ShareError::BadMerkleRoot));
}

#[test]
fn duplicates_fees_without_txs_and_too_many_txs_are_rejected() {
    let (l, tx, _, _) = setup();
    let mut sc = ShareChain::new(PARAMS);
    let m = Address([7; 32]);
    let dup = sc.template_with(l.chain(), l.tip_id(), m, ts(&l), vec![tx.clone(), tx.clone()], 2 * FEE).unwrap();
    assert_eq!(sc.add(dup, l.chain(), NOW, &mut SkipPow), Err(ShareError::BadTxs("transacción repetida")));

    let nofee_txs = sc.template_with(l.chain(), l.tip_id(), m, ts(&l), vec![], 5_000).unwrap();
    assert!(matches!(sc.add(nofee_txs, l.chain(), NOW, &mut SkipPow), Err(ShareError::BadCoinbase(_))));

    // la plantilla se niega a pasar de la cota, y un share fabricado a mano tampoco entra
    let many: Vec<Transaction> = vec![tx.clone(); MAX_SHARE_TXS + 1];
    assert!(matches!(sc.template_with(l.chain(), l.tip_id(), m, ts(&l), many.clone(), 0), Err(ShareError::BadTxs(_))));
    let mut s = sc.template(l.chain(), l.tip_id(), m, ts(&l)).unwrap();
    s.txs = many;
    assert!(matches!(sc.add(s, l.chain(), NOW, &mut SkipPow), Err(ShareError::BadTxs(_))));
}

#[test]
fn amounts_must_match_the_declared_fees() {
    let (l, tx, _, _) = setup();
    let mut sc = ShareChain::new(PARAMS);
    let mut s = sc.template_with(l.chain(), l.tip_id(), Address([7; 32]), ts(&l), vec![tx], FEE).unwrap();
    // declara más comisiones sin tocar los montos y rehace la raíz de Merkle (un tramposo coherente)
    s.coinbase.fees += 1;
    let mut leaves = vec![s.coinbase.id()];
    leaves.extend(s.txs.iter().map(|t| t.full_id()));
    s.header.merkle_root = armax_chain::merkle::merkle_root(&leaves);
    assert!(matches!(sc.add(s, l.chain(), NOW, &mut SkipPow), Err(ShareError::BadPayout(_))));
}

#[test]
fn a_false_fee_claim_passes_the_sharechain_but_can_never_become_a_block() {
    let (mut l, tx, _, _) = setup();
    let mut sc = ShareChain::new(PARAMS);
    // montos coherentes con una comisión inventada (la real es FEE): solo el libro mayor lo sabe
    let s = sc.template_with(l.chain(), l.tip_id(), Address([7; 32]), ts(&l), vec![tx.clone()], 999_999).unwrap();
    assert!(matches!(sc.add(s.clone(), l.chain(), NOW, &mut SkipPow), Ok(AddShare::Added { .. })));
    let err = l.add_block(FullBlock { block: s.to_block(), txs: s.txs.clone() }, NOW, &mut SkipPow).unwrap_err();
    assert!(matches!(err, LedgerError::Invalid { reason: InvalidReason::FeesMismatch { .. }, .. }), "{err:?}");
    // la cadena de bloques sigue donde estaba
    assert_eq!(l.tip_height(), 6);
}

#[test]
fn serialization_with_transactions_is_strict() {
    let (l, tx, _, _) = setup();
    let sc = ShareChain::new(PARAMS);
    let s = sc.template_with(l.chain(), l.tip_id(), Address([7; 32]), ts(&l), vec![tx], FEE).unwrap();
    let b = s.to_bytes();
    assert_eq!(Share::from_bytes(&b), Ok(s.clone()));
    let mut longer = b.clone();
    longer.push(0);
    assert!(Share::from_bytes(&longer).is_err());
    for cut in [1usize, 5, 40, 200] {
        assert!(Share::from_bytes(&b[..b.len() - cut]).is_err(), "cut={cut}");
    }
    // un contador de transacciones absurdo se rechaza sin reservar memoria
    let cb_len = s.coinbase.to_bytes().len();
    let n_at = armax_pow::HEADER_LEN + 4 + cb_len;
    let mut evil = b.clone();
    evil[n_at..n_at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(Share::from_bytes(&evil), Err("demasiadas transacciones"));
}
