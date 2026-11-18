//! Pruebas de la sharechain con una `Chain` real. El PoW se omite (`SkipPow`) salvo en las pruebas
//! `real_pow_*`, que usan la VM con `Params::TEST`.

use armax_chain::block::genesis_block;
use armax_chain::{AddOutcome, Address, Chain, DamperParams, Output, SharePowCheck, SkipPow, VmPow};
use armax_pow::consensus::{genesis_epoch_seed, op_table_for_seed, TARGET_BLOCK_TIME};
use armax_pow::validate::mine_at;
use armax_pow::{next_target, BlockHeader, HeaderError, U256};
use armax_share::share::make_extra;
use armax_share::sharechain::{share_target, share_weight};
use armax_share::{AddShare, Share, ShareChain, ShareError, ShareParams, NO_PREV};
use armax_vm::{Native, Params};

type Hash32 = [u8; 32];

const T0: u64 = 1_800_000_000;
const NOW: u64 = T0 + 1_000_000;

fn addr(i: u8) -> Address {
    Address([i; 32])
}

/// Cadena con `n` bloques vacíos (PoW omitido) sobre el génesis; devuelve los ids de cada altura.
fn chain_with(n: usize) -> (Chain, Vec<Hash32>) {
    let mut chain = Chain::new(DamperParams::MAINNET, genesis_block(T0, b"shares")).unwrap();
    let mut ids = vec![chain.genesis_id()];
    for i in 1..=n {
        let b = chain
            .build_template(ids.last().unwrap(), addr(200), T0 + i as u64 * TARGET_BLOCK_TIME, vec![])
            .unwrap();
        let id = b.id();
        assert!(matches!(chain.add_block(b, NOW, &mut SkipPow), Ok(AddOutcome::Extended)));
        ids.push(id);
    }
    (chain, ids)
}

fn ts_after(chain: &Chain, parent: &Hash32) -> u64 {
    chain.header(parent).unwrap().timestamp + TARGET_BLOCK_TIME
}

/// Share manual sobre `parent` con el share anterior `prev` que se quiera (para armar casos que
/// `ShareChain::template` no produciría).
fn craft(sc: &ShareChain, chain: &Chain, parent: Hash32, prev: Option<Hash32>, miner: Address) -> Share {
    let (_, window) = chain.header_context(&parent).unwrap();
    let target = next_target(&window);
    let weight = share_weight(&target, sc.params().ratio);
    let shares = sc.next_payout(prev, miner, weight);
    let extra = make_extra(&prev.unwrap_or(NO_PREV), &miner);
    let b = chain
        .build_template_full(&parent, &shares, ts_after(chain, &parent), extra, 0, vec![])
        .unwrap();
    Share { header: b.header, coinbase: b.coinbase, txs: vec![] }
}

/// Reconstruye cabecera y raíz de Merkle tras cambiar el coinbase (un tramposo coherente).
fn reseal(mut s: Share) -> Share {
    s.header.merkle_root = armax_chain::merkle::merkle_root(&[s.coinbase.id()]);
    s
}

fn add_ok(sc: &mut ShareChain, chain: &Chain, s: Share) -> Hash32 {
    let id = s.id();
    match sc.add(s, chain, NOW, &mut SkipPow) {
        Ok(AddShare::Added { .. }) => id,
        other => panic!("se esperaba Added, salió {other:?}"),
    }
}

fn ppm_of(s: &Share, a: Address) -> u32 {
    s.coinbase.outputs.iter().find(|o| o.address == a).map(|o| o.share_ppm).unwrap_or(0)
}

#[test]
fn shares_chain_up_and_payouts_follow_the_window() {
    let (chain, ids) = chain_with(3);
    let parent = *ids.last().unwrap();
    let mut sc = ShareChain::new(ShareParams::FAST);

    let t = sc.template(&chain, parent, addr(1), ts_after(&chain, &parent)).unwrap();
    assert_eq!(t.meta().unwrap().prev_share, NO_PREV);
    assert_eq!(t.coinbase.outputs.len(), 1, "el primero cobra todo");
    assert_eq!(t.coinbase.outputs[0].share_ppm, 1_000_000);
    let s1 = add_ok(&mut sc, &chain, t);
    assert_eq!(sc.tip(), Some(s1));
    assert_eq!(sc.height_of(&s1), Some(1));

    let t = sc.template(&chain, parent, addr(2), ts_after(&chain, &parent)).unwrap();
    assert_eq!(t.meta().unwrap().prev_share, s1);
    assert_eq!(ppm_of(&t, addr(1)), 500_000);
    assert_eq!(ppm_of(&t, addr(2)), 500_000);
    let s2 = add_ok(&mut sc, &chain, t);

    let t = sc.template(&chain, parent, addr(1), ts_after(&chain, &parent)).unwrap();
    let s3 = add_ok(&mut sc, &chain, t);
    assert_eq!(sc.tip(), Some(s3));
    assert_eq!(sc.height_of(&s3), Some(3));
    assert_eq!(sc.ids_back(&s3, 10), vec![s3, s2, s1]);

    // próximo share de un tercero: ventana A,B,A + C → 50 % / 25 % / 25 %
    let t = sc.template(&chain, parent, addr(3), ts_after(&chain, &parent)).unwrap();
    assert_eq!(ppm_of(&t, addr(1)), 500_000);
    assert_eq!(ppm_of(&t, addr(2)), 250_000);
    assert_eq!(ppm_of(&t, addr(3)), 250_000);
}

#[test]
fn the_window_forgets_old_shares() {
    let (chain, ids) = chain_with(2);
    let parent = *ids.last().unwrap();
    let mut sc = ShareChain::new(ShareParams { ratio: 4, window: 3 });
    for m in [1u8, 1, 2, 2] {
        let t = sc.template(&chain, parent, addr(m), ts_after(&chain, &parent)).unwrap();
        add_ok(&mut sc, &chain, t);
    }
    // ventana de 3 = los 2 últimos (B, B) + el nuevo: A ya no cuenta
    let t = sc.template(&chain, parent, addr(3), ts_after(&chain, &parent)).unwrap();
    assert_eq!(ppm_of(&t, addr(1)), 0);
    assert_eq!(ppm_of(&t, addr(2)), 666_667);
    assert_eq!(ppm_of(&t, addr(3)), 333_333);
}

#[test]
fn duplicate_is_already_known() {
    let (chain, ids) = chain_with(2);
    let parent = *ids.last().unwrap();
    let mut sc = ShareChain::new(ShareParams::FAST);
    let t = sc.template(&chain, parent, addr(1), ts_after(&chain, &parent)).unwrap();
    add_ok(&mut sc, &chain, t.clone());
    assert_eq!(sc.add(t, &chain, NOW, &mut SkipPow), Ok(AddShare::AlreadyKnown));
    assert_eq!(sc.len(), 1);
}

#[test]
fn a_cheater_cannot_redirect_the_payout() {
    let (chain, ids) = chain_with(2);
    let parent = *ids.last().unwrap();
    let mut sc = ShareChain::new(ShareParams::FAST);
    let t = sc.template(&chain, parent, addr(1), ts_after(&chain, &parent)).unwrap();
    add_ok(&mut sc, &chain, t);

    // el tramposo arma un candidato coherente (Merkle y cabecera bien) pero se paga todo
    let ts = ts_after(&chain, &parent);
    let extra = make_extra(&sc.tip().unwrap(), &addr(9));
    let b = chain.build_template_full(&parent, &[(addr(9), 1_000_000)], ts, extra, 0, vec![]).unwrap();
    let evil = Share { header: b.header, coinbase: b.coinbase, txs: vec![] };
    assert!(matches!(sc.add(evil, &chain, NOW, &mut SkipPow), Err(ShareError::BadPayout(_))));

    // y tampoco puede quitarle a otro cambiando una salida de un share legítimo
    let mut t = sc.template(&chain, parent, addr(2), ts_after(&chain, &parent)).unwrap();
    t.coinbase.outputs[0].address = addr(9);
    assert!(matches!(sc.add(reseal(t), &chain, NOW, &mut SkipPow), Err(ShareError::BadPayout(_))));
    assert_eq!(sc.len(), 1);
}

#[test]
fn invented_amounts_are_rejected_so_the_share_could_have_been_a_block() {
    let (chain, ids) = chain_with(2);
    let parent = *ids.last().unwrap();
    let mut sc = ShareChain::new(ShareParams::FAST);
    let mut t = sc.template(&chain, parent, addr(1), ts_after(&chain, &parent)).unwrap();
    t.coinbase.outputs[0].amount += 1;
    assert_eq!(
        sc.add(reseal(t), &chain, NOW, &mut SkipPow),
        Err(ShareError::BadPayout("monto distinto del que exige el consenso"))
    );
}

#[test]
fn body_rules() {
    let (chain, ids) = chain_with(2);
    let parent = *ids.last().unwrap();
    let mut sc = ShareChain::new(ShareParams::FAST);
    let good = sc.template(&chain, parent, addr(1), ts_after(&chain, &parent)).unwrap();

    // extra mal formado
    let mut s = good.clone();
    s.coinbase.extra[0] ^= 1;
    assert_eq!(sc.add(reseal(s), &chain, NOW, &mut SkipPow), Err(ShareError::BadExtra));

    // comisiones distintas de cero
    let mut s = good.clone();
    s.coinbase.fees = 5;
    assert!(matches!(sc.add(reseal(s), &chain, NOW, &mut SkipPow), Err(ShareError::BadCoinbase(_))));

    // altura del coinbase
    let mut s = good.clone();
    s.coinbase.height += 1;
    assert!(matches!(sc.add(reseal(s), &chain, NOW, &mut SkipPow), Err(ShareError::BadCoinbase(_))));

    // raíz de Merkle que no es la del coinbase
    let mut s = good.clone();
    s.header.merkle_root[0] ^= 1;
    assert_eq!(sc.add(s, &chain, NOW, &mut SkipPow), Err(ShareError::BadMerkleRoot));
    assert!(sc.is_empty());
}

#[test]
fn orphans_are_reported_as_such() {
    let (chain, ids) = chain_with(2);
    let parent = *ids.last().unwrap();
    let mut sc = ShareChain::new(ShareParams::FAST);
    let good = sc.template(&chain, parent, addr(1), ts_after(&chain, &parent)).unwrap();

    // share anterior desconocido
    let mut s = good.clone();
    s.coinbase.extra = make_extra(&[9; 32], &addr(1));
    let e = sc.add(reseal(s), &chain, NOW, &mut SkipPow).unwrap_err();
    assert_eq!(e, ShareError::UnknownPrevShare);
    assert!(e.is_orphan());

    // bloque padre desconocido
    let mut s = good.clone();
    s.header.prev_hash = [7; 32];
    let e = sc.add(s, &chain, NOW, &mut SkipPow).unwrap_err();
    assert_eq!(e, ShareError::UnknownParent);
    assert!(e.is_orphan());

    // un error de verdad no es huérfano
    assert!(!ShareError::BadExtra.is_orphan());
    assert!(!ShareError::BadPayout("x").is_orphan());
}

#[test]
fn header_rules_apply_like_for_blocks() {
    let (chain, ids) = chain_with(3);
    let parent = *ids.last().unwrap();
    let mut sc = ShareChain::new(ShareParams::FAST);
    let good = sc.template(&chain, parent, addr(1), ts_after(&chain, &parent)).unwrap();

    // el minero no elige su target
    let mut s = good.clone();
    s.header.target = s.header.target.shr(1);
    assert!(matches!(sc.add(s, &chain, NOW, &mut SkipPow), Err(ShareError::Header(HeaderError::TargetMismatch { .. }))));

    // hora demasiado en el futuro
    let mut s = good.clone();
    s.header.timestamp = NOW + 100_000;
    assert!(matches!(
        sc.add(s, &chain, NOW, &mut SkipPow),
        Err(ShareError::Header(HeaderError::TimestampTooFarInFuture { .. }))
    ));

    // hora que no pasa la mediana
    let mut s = good.clone();
    s.header.timestamp = T0;
    assert!(matches!(
        sc.add(s, &chain, NOW, &mut SkipPow),
        Err(ShareError::Header(HeaderError::TimestampNotAfterMedian { .. }))
    ));
}

#[test]
fn block_height_may_not_regress_along_the_sharechain() {
    let (chain, ids) = chain_with(6);
    let mut sc = ShareChain::new(ShareParams::FAST);
    let new_parent = ids[5];
    let old_parent = ids[3];

    let a = craft(&sc, &chain, new_parent, None, addr(1));
    let a_id = add_ok(&mut sc, &chain, a);

    // un share sobre un padre más viejo que el del share anterior: rancio, se rechaza
    let stale = craft(&sc, &chain, old_parent, Some(a_id), addr(2));
    assert_eq!(sc.add(stale, &chain, NOW, &mut SkipPow), Err(ShareError::ParentRegresses));
    // y la plantilla tampoco lo produce
    assert_eq!(
        sc.template(&chain, old_parent, addr(2), ts_after(&chain, &old_parent)).unwrap_err(),
        ShareError::ParentRegresses
    );

    // el mismo padre o uno más nuevo sí valen
    let same = craft(&sc, &chain, new_parent, Some(a_id), addr(2));
    add_ok(&mut sc, &chain, same);
    let newer = craft(&sc, &chain, ids[6], sc.tip(), addr(3));
    add_ok(&mut sc, &chain, newer);
}

#[test]
fn the_heaviest_branch_wins_and_ties_keep_the_first() {
    let (chain, ids) = chain_with(3);
    let parent = *ids.last().unwrap();
    let mut sc = ShareChain::new(ShareParams::FAST);

    let sh = craft(&sc, &chain, parent, None, addr(1));
    let root = add_ok(&mut sc, &chain, sh);
    // rama X: un share más
    let sh = craft(&sc, &chain, parent, Some(root), addr(2));
    let x1 = add_ok(&mut sc, &chain, sh);
    assert_eq!(sc.tip(), Some(x1));
    // rama Y desde la raíz, mismo peso: la primera vista se mantiene
    let sh = craft(&sc, &chain, parent, Some(root), addr(3));
    let y1 = add_ok(&mut sc, &chain, sh);
    assert_eq!(sc.tip(), Some(x1), "empate: gana la primera vista");
    assert_ne!(x1, y1);
    // Y se alarga y pasa a X
    let sh = craft(&sc, &chain, parent, Some(y1), addr(3));
    let y2 = add_ok(&mut sc, &chain, sh);
    assert_eq!(sc.tip(), Some(y2));
    assert_eq!(sc.ids_back(&y2, 10), vec![y2, y1, root]);
}

#[test]
fn share_weight_and_target_scale_with_the_ratio() {
    let (chain, ids) = chain_with(1);
    let (_, window) = chain.header_context(&ids[1]).unwrap();
    let t = next_target(&window);
    assert_eq!(share_target(&t, 1), t);
    let t4 = share_target(&t, 4);
    assert!(t4 > t);
    // un share de umbral 4 veces más fácil pesa ~4 veces menos que un bloque
    let w1 = share_weight(&t, 1);
    let w4 = share_weight(&t, 4);
    assert!((w1 / 4).abs_diff(w4) <= 1, "w1={w1} w4={w4}");
    // saturación en el límite de PoW
    assert!(share_target(&U256::MAX, 16) <= armax_pow::consensus::pow_limit());
    assert!(share_weight(&t, 1) >= 1);
}

/// PoW que devuelve un digest fijo si cumple el umbral (para probar `is_block`).
struct Fixed(U256);

impl SharePowCheck for Fixed {
    fn check_at(&mut self, _: &BlockHeader, _: &[u8; 32], target: &U256) -> Result<[u8; 32], HeaderError> {
        if self.0 <= *target {
            Ok(self.0.to_be_bytes())
        } else {
            Err(HeaderError::InsufficientWork)
        }
    }
}

#[test]
fn is_block_only_when_the_digest_meets_the_block_target() {
    let (chain, ids) = chain_with(2);
    let parent = *ids.last().unwrap();
    let (_, window) = chain.header_context(&parent).unwrap();
    let block_target = next_target(&window);
    let mut sc = ShareChain::new(ShareParams::FAST);

    // digest entre el target del bloque y el del share (ratio 4): solo share
    let between = block_target.mul_div_u64(2, 1).unwrap();
    let s = sc.template(&chain, parent, addr(1), ts_after(&chain, &parent)).unwrap();
    assert_eq!(
        sc.add(s, &chain, NOW, &mut Fixed(between)),
        Ok(AddShare::Added { new_tip: true, is_block: false })
    );
    // digest bajo el target del bloque: es un bloque
    let s = sc.template(&chain, parent, addr(2), ts_after(&chain, &parent)).unwrap();
    assert_eq!(
        sc.add(s, &chain, NOW, &mut Fixed(block_target)),
        Ok(AddShare::Added { new_tip: true, is_block: true })
    );
    // digest que ni cumple el share: rechazado y no se guarda
    let before = sc.len();
    let s = sc.template(&chain, parent, addr(3), ts_after(&chain, &parent)).unwrap();
    let too_big = block_target.mul_div_u64(100, 1).unwrap();
    assert_eq!(
        sc.add(s, &chain, NOW, &mut Fixed(too_big)),
        Err(ShareError::Header(HeaderError::InsufficientWork))
    );
    assert_eq!(sc.len(), before);
}

#[test]
fn memory_is_bounded_by_pruning() {
    let (chain, ids) = chain_with(2);
    let parent = *ids.last().unwrap();
    let mut sc = ShareChain::new(ShareParams { ratio: 4, window: 8 });
    for i in 0..200u32 {
        let t = sc.template(&chain, parent, addr((i % 5) as u8 + 1), ts_after(&chain, &parent)).unwrap();
        add_ok(&mut sc, &chain, t);
    }
    // se guardan unas 2 ventanas y pico, no los 200
    assert!(sc.len() < 80, "len={}", sc.len());
    assert!(sc.tip().is_some());
    // y se puede seguir construyendo sobre la punta
    let t = sc.template(&chain, parent, addr(9), ts_after(&chain, &parent)).unwrap();
    add_ok(&mut sc, &chain, t);
}

#[test]
fn real_pow_share_found_at_the_easy_target_and_as_a_block() {
    let params = Params::TEST;
    let table = op_table_for_seed(&genesis_epoch_seed());
    let mut scratch = vec![0u8; params.scratch_bytes];
    let mut chain = Chain::new(DamperParams::MAINNET, genesis_block(T0, b"real shares")).unwrap();
    let mut pow = VmPow::<Native>::new(params).unwrap();
    let g = chain.genesis_id();
    let mut sc = ShareChain::new(ShareParams::FAST);

    // 1. un share minado al umbral fácil (ratio 4) se valida con la VM real
    let mut s = sc.template(&chain, g, addr(1), T0 + TARGET_BLOCK_TIME).unwrap();
    let easy = share_target(&s.header.target, sc.params().ratio);
    let (nonce, _) = mine_at::<Native>(&s.header, &easy, &params, &table, &mut scratch, 0, 200_000, &mut || false)
        .expect("200000 intentos bastan");
    s.header.nonce = nonce;
    let id = s.id();
    let r = sc.add(s.clone(), &chain, NOW, &mut pow).unwrap();
    assert!(matches!(r, AddShare::Added { new_tip: true, .. }));
    assert_eq!(sc.tip(), Some(id));

    // 2. con otro nonce que no cumple ni el umbral fácil, se rechaza (no se guarda)
    let mut bad = sc.template(&chain, g, addr(2), T0 + TARGET_BLOCK_TIME).unwrap();
    let mut n = 0u64;
    loop {
        bad.header.nonce = n;
        if mine_at::<Native>(&bad.header, &easy, &params, &table, &mut scratch, n, 1, &mut || false).is_none() {
            break;
        }
        n += 1;
    }
    assert_eq!(
        sc.add(bad, &chain, NOW, &mut pow),
        Err(ShareError::Header(HeaderError::InsufficientWork))
    );
    assert_eq!(sc.len(), 1);

    // 3. un share minado al target del bloque además es un bloque válido para la cadena
    let mut blk = sc.template(&chain, g, addr(3), T0 + TARGET_BLOCK_TIME).unwrap();
    let hard = blk.header.target;
    let (nonce, _) = mine_at::<Native>(&blk.header, &hard, &params, &table, &mut scratch, 0, 400_000, &mut || false)
        .expect("400000 intentos bastan para dificultad 1500");
    blk.header.nonce = nonce;
    let r = sc.add(blk.clone(), &chain, NOW, &mut pow).unwrap();
    assert_eq!(r, AddShare::Added { new_tip: true, is_block: true });
    let block = blk.to_block();
    let bid = block.id();
    assert_eq!(chain.add_block(block, NOW, &mut pow), Ok(AddOutcome::Extended));
    // el reparto del bloque es el de la sharechain: los dos mineros anteriores y el que lo halló
    let outs: &[Output] = chain.payouts_of(&bid).unwrap();
    assert_eq!(outs.len(), 2, "A (share 1) y C (el bloque); B no aportó nada válido");
    assert_eq!(outs.iter().map(|o| o.share_ppm).sum::<u32>(), 1_000_000);
    assert_eq!(chain.reward_of(&bid), Some(25 * armax_chain::COIN));
}

#[test]
fn a_node_can_start_at_a_peers_horizon_and_then_validates_normally() {
    let params = ShareParams { ratio: 4, window: 8 };
    let (chain, ids) = chain_with(2);
    let parent = *ids.last().unwrap();
    let mut full = ShareChain::new(params);
    let mut all = vec![];
    for i in 0..30u8 {
        let t = full.template(&chain, parent, addr(1 + i % 3), ts_after(&chain, &parent)).unwrap();
        all.push(t.clone());
        add_ok(&mut full, &chain, t);
    }

    // quien llega tarde no tiene el anterior del 12º: es un huérfano normal...
    let mut late = ShareChain::new(params);
    assert_eq!(late.add(all[12].clone(), &chain, NOW, &mut SkipPow), Err(ShareError::UnknownPrevShare));
    // ...pero puede arrancar en él como base, y el resto se encadena con normalidad
    assert!(matches!(late.add_base(all[12].clone(), &chain, NOW, &mut SkipPow), Ok(AddShare::Added { .. })));
    for s in &all[13..] {
        assert!(matches!(late.add(s.clone(), &chain, NOW, &mut SkipPow), Ok(AddShare::Added { .. })));
    }
    assert_eq!(late.tip(), full.tip());
    for m in 1..=3 {
        assert_eq!(late.miner_ppm(&addr(m)), full.miner_ppm(&addr(m)));
    }

    // pasada una ventana desde la base, el reparto se vuelve a exigir
    let mut cheat = craft(&late, &chain, parent, late.tip(), addr(9));
    cheat.coinbase.outputs[0].address = addr(77);
    let cheat = reseal(cheat);
    assert!(matches!(late.add(cheat, &chain, NOW, &mut SkipPow), Err(ShareError::BadPayout(_))));

    // con la sharechain ya iniciada, un share de un anterior desconocido sigue siendo huérfano
    assert_eq!(late.add_base(all[3].clone(), &chain, NOW, &mut SkipPow), Err(ShareError::UnknownPrevShare));
}

#[test]
fn a_base_with_a_forged_payout_after_its_window_is_rejected_but_shares_before_it_are_not_checked() {
    // el reparto de los primeros `window - 1` shares tras la base no se puede comprobar (falta
    // historia): se admiten; el siguiente ya lleva una ventana completa y se exige
    let params = ShareParams { ratio: 4, window: 4 };
    let (chain, ids) = chain_with(1);
    let parent = *ids.last().unwrap();
    let mut full = ShareChain::new(params);
    let mut all = vec![];
    for i in 0..12u8 {
        let t = full.template(&chain, parent, addr(1 + i % 2), ts_after(&chain, &parent)).unwrap();
        all.push(t.clone());
        add_ok(&mut full, &chain, t);
    }
    let mut late = ShareChain::new(params);
    late.add_base(all[4].clone(), &chain, NOW, &mut SkipPow).unwrap();
    late.add(all[5].clone(), &chain, NOW, &mut SkipPow).unwrap();
    late.add(all[6].clone(), &chain, NOW, &mut SkipPow).unwrap();
    // base + 2 = 3 = window - 1 shares de historia: desde aquí se exige el reparto
    let mut forged = craft(&late, &chain, parent, late.tip(), addr(5));
    let last = forged.coinbase.outputs.len() - 1;
    assert!(last >= 1);
    forged.coinbase.outputs[0].share_ppm += 1;
    forged.coinbase.outputs[last].share_ppm -= 1;
    let forged = reseal(forged);
    assert!(matches!(late.add(forged, &chain, NOW, &mut SkipPow), Err(ShareError::BadPayout(_))));
}
