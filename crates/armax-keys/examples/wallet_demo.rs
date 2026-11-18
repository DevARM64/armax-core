//! Demostración: crea una cartera de prueba, deriva direcciones y firma un gasto.
//! **Solo para probar**: usa `InsecureTestVault` y muestra la frase en pantalla.
//!   cargo run --release -p armax-keys --example wallet_demo
use armax_keys::address::encode;
use armax_keys::rng::fill_os_random;
use armax_keys::tx::{OutPoint, Transaction, TxOut};
use armax_keys::utxo::{UtxoSet, COINBASE_MATURITY};
use armax_keys::wallet::{InsecureTestVault, Wallet};

fn main() {
    let mut entropy = [0u8; 16];
    let mut vault_key = [0u8; 32];
    fill_os_random(&mut entropy).expect("/dev/urandom");
    fill_os_random(&mut vault_key).expect("/dev/urandom");

    let (wallet, mnemonic) = Wallet::create(InsecureTestVault::new(vault_key), &entropy).unwrap();
    println!("FRASE DE RESPALDO (solo demostración, no la uses con fondos reales):\n  {}\n", mnemonic.phrase());

    let mut addrs = vec![];
    for i in 0..3 {
        let a = wallet.address("", 0, i).unwrap();
        println!("dirección {i}: {}", encode(&a));
        addrs.push(a);
    }

    // un coinbase de 25 ARM para la dirección 0 y un gasto de 10 ARM a la dirección 1
    let chain_id = [0x11u8; 32];
    let k0 = wallet.keypair("", 0, 0).unwrap();
    let mut set = UtxoSet::new();
    set.apply_coinbase([1u8; 32], 1, &[(addrs[0], 25 * 100_000_000)]).unwrap();
    let tx = Transaction::build_signed(
        &[(OutPoint { txid: [1u8; 32], index: 0 }, &k0)],
        vec![
            TxOut { address: addrs[1], amount: 10 * 100_000_000 },
            TxOut { address: addrs[0], amount: 1_499_990_000 }, // cambio: 25 − 10 ARM menos 0.0001 de comisión
        ],
        &chain_id,
    )
    .unwrap();
    let (fee, _) = set.apply_tx(&tx, 1 + COINBASE_MATURITY, &chain_id).unwrap();
    println!("\ntransacción de {} bytes, id {}…, comisión {} unidades", tx.to_bytes().len(), hex8(&tx.txid()), fee);
    println!("saldo dirección 0: {} unidades | dirección 1: {} unidades", set.balance_of(&addrs[0]), set.balance_of(&addrs[1]));
    println!("\nintento de gastar otra vez la misma salida: {:?}", set.apply_tx(&tx, 1 + COINBASE_MATURITY, &chain_id).err());
}

fn hex8(b: &[u8]) -> String {
    b[..8].iter().map(|x| format!("{x:02x}")).collect()
}
