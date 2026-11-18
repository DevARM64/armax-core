//! Construcción de pagos: elige monedas maduras y no comprometidas en el mempool.

use armax_chain::Address;
use armax_keys::ed25519::Keypair;
use armax_keys::tx::{OutPoint, Transaction, TxOut, MAX_TX_INPUTS};
use armax_ledger::Ledger;
use armax_mempool::{Mempool, MempoolConfig};

/// Comisión por defecto: el doble del mínimo del mempool para el tamaño estimado.
pub fn default_fee(n_inputs: usize) -> u64 {
    let size = 2 + 132 * n_inputs as u64 + 40 * 2;
    (size * MempoolConfig::default().min_fee_per_kb).div_ceil(1000) * 2
}

/// Saldo gastable ahora: maduro y no gastado por el mempool.
pub fn spendable(ledger: &Ledger, pool: &Mempool, addr: &Address) -> u128 {
    spendable_coins(ledger, pool, addr).iter().map(|(_, a)| *a as u128).sum()
}

fn spendable_coins(ledger: &Ledger, pool: &Mempool, addr: &Address) -> Vec<(OutPoint, u64)> {
    let next = ledger.tip_height() + 1;
    ledger
        .utxos()
        .utxos_of(addr)
        .into_iter()
        .filter(|(op, u)| !(u.coinbase && next < u.height.saturating_add(ledger.utxos().maturity())) && !pool.is_spent(op))
        .map(|(op, u)| (op, u.amount))
        .collect()
}

/// Paga `amount` a `to` desde `from`, con cambio de vuelta a `from`. `fee = None` usa la comisión
/// por defecto. Usa primero las monedas más grandes (menos entradas, menos firmas).
pub fn build_payment(
    ledger: &Ledger,
    pool: &Mempool,
    key: &Keypair,
    from: &Address,
    to: Address,
    amount: u64,
    fee: Option<u64>,
) -> Result<Transaction, String> {
    if amount == 0 {
        return Err("la cantidad debe ser mayor que 0".into());
    }
    let mut coins = spendable_coins(ledger, pool, from);
    coins.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.txid.cmp(&b.0.txid)).then(a.0.index.cmp(&b.0.index)));
    let mut chosen: Vec<(OutPoint, u64)> = vec![];
    let (mut total, mut fee_used) = (0u128, 0u64);
    for c in coins {
        if chosen.len() == MAX_TX_INPUTS {
            break;
        }
        total += c.1 as u128;
        chosen.push(c);
        fee_used = fee.unwrap_or_else(|| default_fee(chosen.len()));
        if total >= amount as u128 + fee_used as u128 {
            break;
        }
    }
    let need = amount as u128 + fee_used as u128;
    if chosen.is_empty() || total < need {
        let have = crate::format_amount(spendable(ledger, pool, from));
        return Err(format!(
            "saldo gastable insuficiente: {have} ARM (maduro y libre) para {} + comisión {}",
            crate::format_amount(amount as u128),
            crate::format_amount(fee_used as u128)
        ));
    }
    let mut outputs = vec![TxOut { address: to, amount }];
    let change = total - need;
    if change > 0 {
        outputs.push(TxOut { address: *from, amount: change as u64 });
    }
    let inputs: Vec<(OutPoint, &Keypair)> = chosen.iter().map(|(op, _)| (*op, key)).collect();
    Transaction::build_signed(&inputs, outputs, &ledger.chain_id()).map_err(|e| format!("{e:?}"))
}

/// Comisión de `tx` (entradas − salidas) mientras sus entradas siguen sin gastar en el conjunto UTXO.
/// `None` si alguna entrada ya no está (p. ej. la transacción ya se confirmó).
pub fn fee_of(ledger: &Ledger, tx: &Transaction) -> Option<u64> {
    let mut total_in: u128 = 0;
    for i in &tx.inputs {
        total_in += ledger.utxos().get(&i.prev)?.amount as u128;
    }
    let total_out: u128 = tx.outputs.iter().map(|o| o.amount as u128).sum();
    u64::try_from(total_in.checked_sub(total_out)?).ok()
}
