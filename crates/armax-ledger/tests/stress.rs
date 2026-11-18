//! Pruebas de estrés del libro mayor, deterministas (semilla fija).
//!
//! * Árbol aleatorio de bloques (ramas, empates, reorganizaciones, gastos válidos e inválidos):
//!   tras cada bloque, el total de UTXO debe cuadrar con lo emitido menos las comisiones.
//! * Bloques válidos mutados byte a byte: nunca pánico y las mismas invariantes.

use std::collections::HashMap;

use armax_chain::block::genesis_block;
use armax_chain::{Address, DamperParams, SkipPow};
use armax_keys::address::address_from_public_key;
use armax_keys::ed25519::Keypair;
use armax_keys::tx::{OutPoint, Transaction, TxOut};
use armax_ledger::{FullBlock, Ledger};

const T0: u64 = 1_800_000_000;
const NOW: u64 = T0 + 100_000_000;
const STEP: u64 = 300;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn key(n: u8) -> (Keypair, Address) {
    let kp = Keypair::from_seed([n; 32]);
    let a = address_from_public_key(&kp.public_key());
    (kp, a)
}

fn assert_supply(l: &Ledger, ctx: &str) {
    let (utxo, expected) = l.supply();
    assert_eq!(utxo as i128, expected, "el suministro no cuadra: {ctx}");
}

/// Árbol aleatorio. Devuelve el libro mayor y los bloques válidos que se le ofrecieron.
fn random_tree(rng: &mut Rng, steps: usize) -> (Ledger, Vec<FullBlock>) {
    let mut l = Ledger::with_maturity(DamperParams::MAINNET, genesis_block(T0, b"stress"), 1, 3).unwrap();
    let keys: Vec<(Keypair, Address)> = (1..=4).map(key).collect();
    let mut ids: Vec<[u8; 32]> = vec![l.tip_id()];
    let mut miner_of: HashMap<[u8; 32], usize> = HashMap::new();
    let mut offered: Vec<FullBlock> = vec![];
    let (mut ok, mut rejected_blocks, mut with_txs) = (0, 0, 0);

    for step in 0..steps {
        // el padre: casi siempre cerca de la punta, a veces cualquiera (ramas viejas)
        let parent = if rng.below(4) == 0 { ids[rng.below(ids.len())] } else { ids[ids.len() - 1 - rng.below(ids.len().min(6))] };
        let h = l.chain().header(&parent).unwrap().height + 1;
        let who = rng.below(keys.len());

        // a veces, un gasto de una coinbase madura de la cadena principal (puede ser inválido en esta rama)
        let mut txs = vec![];
        let mut fees = 0u64;
        if rng.below(3) == 0 && l.tip_height() > 6 {
            let at = 1 + rng.below((l.tip_height() - 4) as usize) as u64;
            if let Some(src) = l.chain().id_at_height(at) {
                if let (Some(&owner), Some(cb)) = (miner_of.get(&src), l.chain().coinbase_of(&src)) {
                    if let Some(out) = cb.outputs.first() {
                        let fee = rng.below(1000) as u64;
                        let dest = keys[rng.below(keys.len())].1;
                        if out.amount > fee + 1 {
                            if let Ok(tx) = Transaction::build_signed(
                                &[(OutPoint { txid: cb.id(), index: 0 }, &keys[owner].0)],
                                vec![TxOut { address: dest, amount: out.amount - fee }],
                                &l.chain_id(),
                            ) {
                                txs.push(tx);
                                fees = fee;
                                with_txs += 1;
                            }
                        }
                    }
                }
            }
        }
        let leaves = txs.iter().map(|t| t.full_id()).collect();
        let block = match l.chain().build_template_full(
            &parent,
            &[(keys[who].1, 1_000_000)],
            T0 + h * STEP + (step as u64 % 7),
            vec![step as u8],
            fees,
            leaves,
        ) {
            Ok(b) => b,
            Err(_) => {
                // el padre quedó invalidado por un descendiente con gasto inválido: ya no sirve
                if ids.len() > 1 {
                    ids.retain(|x| *x != parent);
                }
                continue;
            }
        };
        let fb = FullBlock { block, txs };
        let id = fb.id();
        let bytes = fb.to_bytes();
        offered.push(FullBlock::from_bytes(&bytes).unwrap());
        match l.add_block(fb, NOW, &mut SkipPow) {
            Ok(_) => {
                ok += 1;
                ids.push(id);
                miner_of.insert(id, who);
            }
            Err(_) => rejected_blocks += 1,
        }
        assert_supply(&l, &format!("paso {step}"));
    }
    eprintln!("árbol: {ok} bloques aceptados, {rejected_blocks} rechazados, {with_txs} con gasto, altura {}", l.tip_height());
    (l, offered)
}

#[test]
fn a_random_block_tree_keeps_the_supply_balanced() {
    for seed in [1u64, 7, 99, 12345, 0xDEAD_BEEF] {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let (l, _) = random_tree(&mut rng, 400);
        assert!(l.tip_height() > 8, "seed {seed}: la cadena casi no avanzó");
        assert_supply(&l, "final");
    }
}

#[test]
fn mutated_blocks_never_panic_and_never_break_the_supply() {
    let mut rng = Rng(0xC0FF_EE00_1234_5678);
    let (mut l, offered) = random_tree(&mut rng, 150);
    let (mut decoded, mut accepted) = (0, 0);
    for i in 0..6000 {
        let src = &offered[rng.below(offered.len())];
        let mut b = src.to_bytes();
        match rng.below(4) {
            0 => {
                let k = rng.below(b.len());
                b[k] ^= 1 << rng.below(8);
            }
            1 => {
                for _ in 0..1 + rng.below(4) {
                    let k = rng.below(b.len());
                    b[k] = rng.next() as u8;
                }
            }
            2 => b.truncate(rng.below(b.len() + 1)),
            _ => {
                let k = rng.below(b.len().saturating_sub(8).max(1));
                if b.len() >= k + 8 {
                    b[k..k + 8].copy_from_slice(&[0xFF; 8]);
                }
            }
        }
        let Ok(fb) = FullBlock::from_bytes(&b) else { continue };
        decoded += 1;
        if l.add_block(fb, NOW, &mut SkipPow).is_ok() {
            accepted += 1;
        }
        if i % 100 == 0 {
            assert_supply(&l, &format!("mutación {i}"));
        }
    }
    eprintln!("mutados: {decoded} decodificados, {accepted} aceptados");
    assert!(decoded > 300);
    assert_supply(&l, "final");
}
