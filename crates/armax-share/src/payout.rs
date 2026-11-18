//! Regla de reparto: de los pesos de la ventana de shares a las salidas del coinbase.
//!
//! Es una función **pura y determinista** (solo enteros): todos los nodos del pool la calculan
//! igual y por eso pueden verificar el coinbase de cada share.
//!
//! ```text
//!   ppm_i = ⌊peso_i · 1,000,000 / total⌋
//!   directas   = las primeras (por peso ↓, dirección ↑) con ppm ≥ MIN_SHARE_PPM, hasta 64
//!   polvo      = el resto (por debajo del mínimo, o más allá de la salida 64)
//! ```
//! El coinbase admite 64 salidas con un mínimo de 0.1 % cada una. Con más mineros que eso, o con
//! mineros pequeños, el "polvo" no puede pagarse en partes diminutas: se reserva **una** salida y
//! una lotería ponderada por peso decide qué minero de polvo la cobra entera. El valor esperado de
//! cada uno es exacto (su peso sobre el total); lo que cambia es que cobra de golpe y no a gotas.
//! La lotería sale de `sha256(semilla ‖ peso total del polvo)`, donde la semilla es el id del share
//! anterior, así que no la controla quien prepara el share.
//!
//! El resto del redondeo (≤ 1,000,000 − Σ⌊ppm⌋) va a la primera salida, para sumar exactamente
//! `SHARE_TOTAL`.

use std::collections::HashMap;

use armax_chain::block::{MAX_COINBASE_OUTPUTS, MIN_SHARE_PPM, SHARE_TOTAL};
use armax_chain::Address;
use armax_vm::sha256::sha256_cat;

type Hash32 = [u8; 32];

/// Reparto (dirección, parte en ppm) para los pesos dados. Los pesos de una misma dirección se
/// suman; los pesos 0 se ignoran. Devuelve vacío solo si no hay peso. El resultado pasa
/// `armax_chain::check_shares`: 1–64 salidas, cada una ≥ `MIN_SHARE_PPM`, direcciones distintas,
/// suma exacta.
pub fn payout(weights: &[(Address, u64)], seed: &Hash32) -> Vec<(Address, u32)> {
    let mut agg: HashMap<Address, u128> = HashMap::new();
    for (a, w) in weights {
        if *w > 0 {
            *agg.entry(*a).or_default() += *w as u128;
        }
    }
    let mut v: Vec<(Address, u128)> = agg.into_iter().collect();
    if v.is_empty() {
        return vec![];
    }
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0 .0.cmp(&b.0 .0)));
    let total: u128 = v.iter().map(|x| x.1).sum();
    let ppm = |w: u128| (w * SHARE_TOTAL as u128 / total) as u32;

    let mut out: Vec<(Address, u32)> = vec![];
    for (a, w) in &v {
        let p = ppm(*w);
        if out.len() >= MAX_COINBASE_OUTPUTS || p < MIN_SHARE_PPM {
            break;
        }
        out.push((*a, p));
    }
    let mut rest: Vec<(Address, u128)> = v[out.len()..].to_vec();
    if !rest.is_empty() && out.len() == MAX_COINBASE_OUTPUTS {
        out.pop(); // deja sitio a la salida de la lotería
        rest = v[out.len()..].to_vec();
    }

    let direct_sum: u64 = out.iter().map(|x| x.1 as u64).sum();
    if rest.is_empty() {
        out[0].1 += (SHARE_TOTAL as u64 - direct_sum) as u32;
        return out;
    }
    let dust_ppm: u64 = rest.iter().map(|x| ppm(x.1) as u64).sum();
    let remainder = SHARE_TOTAL as u64 - direct_sum - dust_ppm;
    if dust_ppm < MIN_SHARE_PPM as u64 && !out.is_empty() {
        // polvo total insignificante: se suma a la primera salida, sin lotería
        out[0].1 += (dust_ppm + remainder) as u32;
        return out;
    }
    let dust_weight: u128 = rest.iter().map(|x| x.1).sum();
    let h = sha256_cat(&[b"ARMX-SHARE-DUST-v1", seed, &dust_weight.to_le_bytes()]);
    let r = u128::from_le_bytes(h[..16].try_into().unwrap()) % dust_weight;
    let mut cum = 0u128;
    let winner = rest
        .iter()
        .find(|(_, w)| {
            cum += *w;
            r < cum
        })
        .expect("r < peso total del polvo")
        .0;
    out.push((winner, dust_ppm as u32));
    out[0].1 += remainder as u32;
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use armax_chain::check_shares;

    fn a(i: u32) -> Address {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&i.to_le_bytes());
        Address(b)
    }

    fn assert_valid(p: &[(Address, u32)]) {
        check_shares(p).expect("el reparto debe ser una forma válida de coinbase");
    }

    #[test]
    fn single_miner_gets_everything() {
        let p = payout(&[(a(1), 7)], &[0; 32]);
        assert_eq!(p, vec![(a(1), 1_000_000)]);
    }

    #[test]
    fn weights_of_the_same_address_add_up_and_zero_is_ignored() {
        let p = payout(&[(a(1), 1), (a(2), 1), (a(1), 2), (a(3), 0)], &[0; 32]);
        assert_eq!(p, vec![(a(1), 750_000), (a(2), 250_000)]);
        assert!(payout(&[(a(1), 0)], &[0; 32]).is_empty());
        assert!(payout(&[], &[0; 32]).is_empty());
    }

    #[test]
    fn order_of_input_does_not_matter_and_ties_break_by_address() {
        let w1 = [(a(5), 10u64), (a(2), 10), (a(9), 30)];
        let w2 = [(a(9), 30u64), (a(5), 10), (a(2), 10)];
        assert_eq!(payout(&w1, &[1; 32]), payout(&w2, &[1; 32]));
        let p = payout(&w1, &[1; 32]);
        assert_eq!(p[0].0, a(9));
        assert_eq!(p[1].0, a(2)); // empate: la dirección menor primero
        assert_eq!(p[2].0, a(5));
        assert_valid(&p);
    }

    #[test]
    fn rounding_remainder_goes_to_the_first_output() {
        let p = payout(&[(a(1), 1), (a(2), 1), (a(3), 1)], &[0; 32]);
        assert_valid(&p);
        assert_eq!(p.iter().map(|x| x.1).sum::<u32>(), 1_000_000);
        assert_eq!(p[1].1, 333_333);
        assert_eq!(p[0].1, 333_334);
    }

    #[test]
    fn up_to_64_big_enough_miners_are_paid_directly_without_lottery() {
        let w: Vec<_> = (0..64).map(|i| (a(i), 100u64)).collect();
        let p = payout(&w, &[3; 32]);
        assert_valid(&p);
        assert_eq!(p.len(), 64);
        // todos cobran directo: la semilla no cambia nada
        assert_eq!(p, payout(&w, &[4; 32]));
    }

    #[test]
    fn more_than_64_miners_use_63_direct_outputs_and_one_lottery_slot() {
        let w: Vec<_> = (0..100).map(|i| (a(i), 100u64)).collect();
        let p = payout(&w, &[3; 32]);
        assert_valid(&p);
        assert_eq!(p.len(), 64);
        // la salida de la lotería agrupa a los 37 mineros restantes: ≈ 37 %
        let lottery = p[63].1;
        assert!((369_000..=371_000).contains(&lottery), "lottery={lottery}");
        // los 63 directos son los de dirección menor (empate de pesos)
        for (i, (addr, _)) in p[..63].iter().enumerate() {
            assert_eq!(*addr, a(i as u32));
        }
    }

    #[test]
    fn tiny_miners_only_are_settled_by_lottery() {
        // 2,000 mineros con 0.05 % cada uno: ninguno llega al mínimo
        let w: Vec<_> = (0..2000).map(|i| (a(i), 1u64)).collect();
        let p = payout(&w, &[0; 32]);
        assert_valid(&p);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].1, 1_000_000);
        // otra semilla, otro ganador; y con 400 semillas ganan muchos distintos
        let mut winners = std::collections::HashSet::new();
        for s in 0..400u32 {
            let mut seed = [0u8; 32];
            seed[..4].copy_from_slice(&s.to_le_bytes());
            winners.insert(payout(&w, &seed)[0].0);
        }
        assert!(winners.len() > 250, "ganadores distintos: {}", winners.len());
    }

    #[test]
    fn lottery_is_fair_in_expectation() {
        // 70 mineros de peso 100 + uno de 6000 → 63 salidas directas y el resto, a lotería.
        // Entre los de polvo hay uno de peso 30 y otro de peso 1: el primero debe ganar ~30 veces más.
        let mut w: Vec<(Address, u64)> = (100..170u32).map(|i| (a(i), 100)).collect();
        w.push((a(0), 6000));
        w.push((a(1), 30));
        for i in 2..=70u32 {
            w.push((a(i), 1));
        }
        let (mut heavy, mut light) = (0u32, 0u32);
        for s in 0..4000u32 {
            let mut seed = [0u8; 32];
            seed[..4].copy_from_slice(&s.to_le_bytes());
            let p = payout(&w, &seed);
            assert_valid(&p);
            assert_eq!(p.len(), 64);
            let winner = p[63].0;
            if winner == a(1) {
                heavy += 1;
            } else if winner == a(2) {
                light += 1;
            }
        }
        // esperados ≈ 133 y ≈ 4; la cota deja un margen enorme para la varianza
        assert!((70..230).contains(&heavy), "heavy={heavy}");
        assert!(light < 25, "light={light}");
    }

    #[test]
    fn tiny_dust_next_to_a_big_miner_is_absorbed_without_lottery() {
        // 1 minero enorme y 3 con partes de ~0.0003 %: el polvo total < 0.1 %, se suma al primero
        let p = payout(&[(a(1), 10_000_000), (a(2), 10), (a(3), 10), (a(4), 10)], &[0; 32]);
        assert_valid(&p);
        assert_eq!(p, vec![(a(1), 1_000_000)]);
    }

    #[test]
    fn invariants_hold_for_pseudo_random_windows() {
        let mut state = 0x1234_5678_9abc_def0u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..300 {
            let n = (next() % 200 + 1) as u32;
            let w: Vec<_> = (0..n).map(|i| (a(i), next() % 1_000 + 1)).collect();
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&next().to_le_bytes());
            let p = payout(&w, &seed);
            assert_valid(&p);
            assert_eq!(p, payout(&w, &seed), "determinista");
        }
        // pesos enormes no desbordan
        let w: Vec<_> = (0..500u32).map(|i| (a(i), u64::MAX - i as u64)).collect();
        assert_valid(&payout(&w, &[0; 32]));
    }
}
