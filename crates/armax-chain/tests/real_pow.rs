//! Prueba de punta a punta con PoW real (VM con `Params::TEST`, no los 384 MiB de consenso):
//! se mina con la VM, se valida a través de `Chain` con `VmPow`, y se comprueba que un bloque
//! con nonce inválido se rechaza.

use armax_chain::block::genesis_block;
use armax_chain::{Address, AddOutcome, Chain, ChainError, DamperParams, PowCheck, VmPow};
use armax_pow::consensus::{genesis_epoch_seed, op_table_for_seed, TARGET_BLOCK_TIME};
use armax_pow::validate::mine;
use armax_pow::HeaderError;
use armax_vm::{Native, Params};

const T0: u64 = 1_800_000_000;
const NOW: u64 = T0 + 10_000;

#[test]
fn mine_validate_and_reject_with_real_pow() {
    let params = Params::TEST;
    let table = op_table_for_seed(&genesis_epoch_seed());
    let mut scratch = vec![0u8; params.scratch_bytes];

    let mut chain = Chain::new(DamperParams::MAINNET, genesis_block(T0, b"real pow")).unwrap();
    let mut pow = VmPow::<Native>::new(params).unwrap();
    let miner = Address([7u8; 32]);

    let mut parent = chain.genesis_id();
    let mut ts = T0;
    for height in 1..=2u64 {
        ts += TARGET_BLOCK_TIME;
        let mut block = chain.build_template(&parent, miner, ts, vec![]).unwrap();

        // Un nonce sin minar casi seguro no cumple (dificultad inicial = 600): se rechaza.
        let unmined = chain.add_block(block.clone(), NOW, &mut pow);
        assert_eq!(unmined, Err(ChainError::Header(HeaderError::InsufficientWork)), "altura {height}");
        assert!(!chain.contains(&block.id()));

        // Minar de verdad (≈600 intentos de ~3 ms con Params::TEST).
        let (nonce, _) = mine::<Native>(
            &block.header,
            &params,
            &table,
            &mut scratch,
            0,
            100_000,
            &mut || false,
        )
        .expect("100000 intentos bastan para dificultad 600");
        block.header.nonce = nonce;

        assert_eq!(chain.add_block(block.clone(), NOW, &mut pow), Ok(AddOutcome::Extended));
        parent = block.id();
        assert_eq!(chain.tip_height(), height);
    }
}

#[test]
fn vm_pow_receives_the_epoch_seed_of_the_chain() {
    // Un PowCheck espía comprueba que la cadena entrega la semilla de la época 0.
    struct Spy(Vec<[u8; 32]>);
    impl PowCheck for Spy {
        fn check(&mut self, _: &armax_pow::BlockHeader, seed: &[u8; 32]) -> Result<(), HeaderError> {
            self.0.push(*seed);
            Ok(())
        }
    }
    let mut chain = Chain::new(DamperParams::MAINNET, genesis_block(T0, b"spy")).unwrap();
    let g = chain.genesis_id();
    let b = chain.build_template(&g, Address([1; 32]), T0 + TARGET_BLOCK_TIME, vec![]).unwrap();
    let mut spy = Spy(vec![]);
    chain.add_block(b, NOW, &mut spy).unwrap();
    assert_eq!(spy.0, vec![genesis_epoch_seed()]);
}

#[test]
fn split_coinbase_mined_with_real_pow() {
    let params = Params::TEST;
    let table = op_table_for_seed(&genesis_epoch_seed());
    let mut scratch = vec![0u8; params.scratch_bytes];
    let mut chain = Chain::new(DamperParams::MAINNET, genesis_block(T0, b"split")).unwrap();
    let mut pow = VmPow::<Native>::new(params).unwrap();

    let parts = [(Address([1; 32]), 700_000u32), (Address([2; 32]), 200_000), (Address([3; 32]), 100_000)];
    let g = chain.genesis_id();
    let mut block = chain.build_template_split(&g, &parts, T0 + TARGET_BLOCK_TIME, vec![]).unwrap();
    let (nonce, _) = mine::<Native>(&block.header, &params, &table, &mut scratch, 0, 100_000, &mut || false)
        .expect("100000 intentos bastan");
    block.header.nonce = nonce;
    let id = block.id();
    assert_eq!(chain.add_block(block, NOW, &mut pow), Ok(AddOutcome::Extended));
    let outs = chain.payouts_of(&id).unwrap();
    assert_eq!(outs.len(), 3);
    assert_eq!(outs[0].amount, 25 * armax_chain::COIN * 7 / 10);
    assert_eq!(chain.reward_of(&id), Some(25 * armax_chain::COIN));
}
