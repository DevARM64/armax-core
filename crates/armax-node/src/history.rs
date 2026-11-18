//! Historial de la cartera: lo minado, recibido y enviado por una dirección.
//!
//! Se calcula recorriendo la cadena principal de la punta hacia atrás (no se guarda nada
//! aparte: es una vista de lo que ya está en `blocks.db`), más lo que espera en el mempool.
//!
//! * `Mined`: el coinbase de un bloque (o un share del pool) paga a la dirección.
//! * `Received`: una transacción de otra persona paga a la dirección.
//! * `Sent`: una transacción firmada con la llave de la dirección paga a otras direcciones;
//!   `amount` es lo que fue a otros (sin el cambio que vuelve a la propia dirección).
//! * `Internal`: una transacción firmada por la dirección que solo se paga a sí misma.
//!
//! La comisión de un envío no se calcula aquí: las entradas ya no están en el conjunto de UTXO
//! y reconstruirlas obligaría a recorrer toda la cadena.

use armax_chain::Address;
use armax_keys::address::address_from_public_key;
use armax_keys::tx::Transaction;
use armax_ledger::Ledger;
use armax_mempool::Mempool;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Mined,
    Received,
    Sent,
    Internal,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Mined => "mined",
            Kind::Received => "received",
            Kind::Sent => "sent",
            Kind::Internal => "internal",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub kind: Kind,
    /// Unidades (1 ARM = 100,000,000).
    pub amount: u64,
    /// Altura del bloque; `None` si la transacción aún está en el mempool.
    pub height: Option<u64>,
    pub timestamp: Option<u64>,
    pub txid: Option<[u8; 32]>,
    /// La otra parte: el destinatario de un envío o la dirección que firmó un pago recibido.
    pub counterparty: Option<Address>,
    /// Bloques que la confirman (0 = pendiente).
    pub confirmations: u64,
    /// Bloques que faltan para poder gastar lo minado (0 = ya maduro; siempre 0 si no es `Mined`).
    pub matures_in: u64,
    /// Comisión pagada (solo en envíos hechos desde este nodo; ver `sentlog`).
    pub fee: Option<u64>,
}

/// Qué es `tx` para la dirección `me`: tipo, cantidad y la otra parte. `None` si no la toca.
pub fn classify(tx: &Transaction, me: &Address) -> Option<(Kind, u64, Option<Address>)> {
    let signed_by_me = tx.inputs.iter().any(|i| address_from_public_key(&i.public_key) == *me);
    let to_me: u64 = tx.outputs.iter().filter(|o| o.address == *me).map(|o| o.amount).sum();
    let to_others: u64 = tx.outputs.iter().filter(|o| o.address != *me).map(|o| o.amount).sum();
    if signed_by_me {
        if to_others > 0 {
            let first = tx.outputs.iter().find(|o| o.address != *me).map(|o| o.address);
            Some((Kind::Sent, to_others, first))
        } else {
            Some((Kind::Internal, to_me, None))
        }
    } else if to_me > 0 {
        let from = tx.inputs.first().map(|i| address_from_public_key(&i.public_key));
        Some((Kind::Received, to_me, from))
    } else {
        None
    }
}

/// Las `limit` entradas más recientes (primero lo pendiente, luego de la punta hacia atrás).
/// Recorrer una cadena larga sin movimientos de la dirección cuesta tiempo lineal.
pub fn history(ledger: &Ledger, pool: &Mempool, me: &Address, limit: usize) -> Vec<Entry> {
    let mut out: Vec<Entry> = Vec::new();

    for tx in pool.candidates() {
        if out.len() >= limit {
            return out;
        }
        if let Some((kind, amount, counterparty)) = classify(&tx, me) {
            out.push(Entry {
                kind,
                amount,
                height: None,
                timestamp: None,
                txid: Some(tx.txid()),
                counterparty,
                confirmations: 0,
                matures_in: 0,
                fee: None,
            });
        }
    }

    let tip = ledger.tip_height();
    let maturity = ledger.utxos().maturity();
    let chain = ledger.chain();
    let mut h = tip;
    while h >= 1 && out.len() < limit {
        if let Some(id) = chain.id_at_height(h) {
            if let Some(fb) = ledger.full_block(&id) {
                let confirmations = tip - h + 1;
                let timestamp = Some(fb.block.header.timestamp);
                // la transacción más tardía del bloque primero: así el orden es de más nuevo a más viejo
                for tx in fb.txs.iter().rev() {
                    if let Some((kind, amount, counterparty)) = classify(tx, me) {
                        out.push(Entry {
                            kind,
                            amount,
                            height: Some(h),
                            timestamp,
                            txid: Some(tx.txid()),
                            counterparty,
                            confirmations,
                            matures_in: 0,
                            fee: None,
                        });
                    }
                }
                let mined: u64 = fb.block.coinbase.outputs.iter().filter(|o| o.address == *me).map(|o| o.amount).sum();
                if mined > 0 {
                    out.push(Entry {
                        kind: Kind::Mined,
                        amount: mined,
                        height: Some(h),
                        timestamp,
                        txid: None,
                        counterparty: None,
                        confirmations,
                        // lo minado se gasta cuando la punta llega a `altura + madurez`
                        matures_in: (h + maturity).saturating_sub(tip),
                        fee: None,
                    });
                }
            }
        }
        h -= 1;
    }
    out.truncate(limit);
    out
}
