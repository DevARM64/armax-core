//! Conjunto de salidas gastables (UTXO) y reglas con estado: existencia, dueño, madurez del
//! coinbase, comisión y protección contra el doble gasto.
//!
//! Cada operación es atómica: si falla, el conjunto queda como estaba. Cada operación que
//! cambia el conjunto devuelve un `Undo` para revertirla (reorganizaciones de cadena); los `Undo`
//! deben aplicarse en orden inverso al de las operaciones.

use core::fmt;
use std::collections::HashMap;

use armax_chain::Address;

use crate::address::address_from_public_key;
use crate::tx::{Hash32, OutPoint, Transaction, TxError, VerifiedTx};

/// Bloques que deben pasar antes de gastar una salida de coinbase (≈ 8 h con bloques de 300 s):
/// protege a quien recibe de un reorg corto que anule la emisión.
pub const COINBASE_MATURITY: u64 = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Utxo {
    pub address: Address,
    pub amount: u64,
    /// Altura del bloque que la creó.
    pub height: u64,
    pub coinbase: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum UtxoError {
    Tx(TxError),
    /// La entrada `i` no existe o ya se gastó (doble gasto).
    MissingInput(usize),
    /// La clave pública de la entrada `i` no corresponde a la dirección de la salida que gasta.
    WrongOwner(usize),
    /// La entrada `i` gasta un coinbase que aún no madura.
    ImmatureCoinbase(usize),
    /// Las salidas suman más que las entradas.
    OutputsExceedInputs { inputs: u128, outputs: u128 },
    /// Una salida nueva ya existe (mismo txid e índice).
    DuplicateOutput(OutPoint),
}

impl From<TxError> for UtxoError {
    fn from(e: TxError) -> Self {
        UtxoError::Tx(e)
    }
}

impl fmt::Display for UtxoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for UtxoError {}

/// Lo necesario para deshacer una operación.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Undo {
    spent: Vec<(OutPoint, Utxo)>,
    created: Vec<OutPoint>,
}

#[derive(Debug)]
pub struct UtxoSet {
    map: HashMap<OutPoint, Utxo>,
    maturity: u64,
}

impl Default for UtxoSet {
    fn default() -> Self {
        UtxoSet { map: HashMap::new(), maturity: COINBASE_MATURITY }
    }
}

impl UtxoSet {
    pub fn new() -> Self {
        Self::default()
    }
    /// Conjunto con otra madurez de coinbase: **solo para redes de prueba** (en la red real es
    /// `COINBASE_MATURITY`, parte del consenso).
    pub fn with_maturity(maturity: u64) -> Self {
        UtxoSet { map: HashMap::new(), maturity }
    }
    pub fn maturity(&self) -> u64 {
        self.maturity
    }

    pub fn get(&self, op: &OutPoint) -> Option<&Utxo> {
        self.map.get(op)
    }
    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    /// Suma de todos los montos (para auditar contra la emisión).
    pub fn total_amount(&self) -> u128 {
        self.map.values().map(|u| u.amount as u128).sum()
    }
    /// Salidas de una dirección, en orden determinista (altura, txid, índice). Recorre el conjunto.
    pub fn utxos_of(&self, addr: &Address) -> Vec<(OutPoint, Utxo)> {
        let mut v: Vec<(OutPoint, Utxo)> =
            self.map.iter().filter(|(_, u)| u.address == *addr).map(|(o, u)| (*o, *u)).collect();
        v.sort_by(|a, b| (a.1.height, a.0.txid, a.0.index).cmp(&(b.1.height, b.0.txid, b.0.index)));
        v
    }
    /// Saldo de una dirección (recorre el conjunto; la cartera real mantendrá un índice).
    pub fn balance_of(&self, addr: &Address) -> u128 {
        self.map.values().filter(|u| u.address == *addr).map(|u| u.amount as u128).sum()
    }

    /// Registra las salidas de un coinbase. `txid` es el id del coinbase (único por altura).
    /// Las salidas con monto 0 (subsidio agotado) no crean UTXO.
    pub fn apply_coinbase(
        &mut self,
        txid: Hash32,
        height: u64,
        outputs: &[(Address, u64)],
    ) -> Result<Undo, UtxoError> {
        let new: Vec<(OutPoint, Utxo)> = outputs
            .iter()
            .enumerate()
            .filter(|(_, (_, amount))| *amount > 0)
            .map(|(i, (address, amount))| {
                (
                    OutPoint { txid, index: i as u32 },
                    Utxo { address: *address, amount: *amount, height, coinbase: true },
                )
            })
            .collect();
        if let Some((op, _)) = new.iter().find(|(op, _)| self.map.contains_key(op)) {
            return Err(UtxoError::DuplicateOutput(*op));
        }
        let mut undo = Undo::default();
        for (op, u) in new {
            self.map.insert(op, u);
            undo.created.push(op);
        }
        Ok(undo)
    }

    /// Valida (reglas sin estado y con estado) y aplica una transacción en un bloque de altura
    /// `height`. Devuelve la comisión y el `Undo`.
    pub fn apply_tx(
        &mut self,
        tx: &Transaction,
        height: u64,
        chain_id: &Hash32,
    ) -> Result<(u64, Undo), UtxoError> {
        let v = tx.verify(chain_id)?;
        self.apply_verified(v, height)
    }

    /// Igual que `apply_tx` para una transacción ya verificada (p. ej. con `verify_batch`).
    pub fn apply_verified(&mut self, tx: VerifiedTx<'_>, height: u64) -> Result<(u64, Undo), UtxoError> {
        let tx = tx.tx();
        let mut spent = Vec::with_capacity(tx.inputs.len());
        let mut total_in = 0u128;
        for (i, inp) in tx.inputs.iter().enumerate() {
            let u = self.map.get(&inp.prev).ok_or(UtxoError::MissingInput(i))?;
            if address_from_public_key(&inp.public_key) != u.address {
                return Err(UtxoError::WrongOwner(i));
            }
            if u.coinbase && height < u.height.saturating_add(self.maturity) {
                return Err(UtxoError::ImmatureCoinbase(i));
            }
            total_in += u.amount as u128;
            spent.push((inp.prev, *u));
        }
        let total_out = tx.output_total();
        if total_out > total_in {
            return Err(UtxoError::OutputsExceedInputs { inputs: total_in, outputs: total_out });
        }
        let txid = tx.txid();
        let new: Vec<(OutPoint, Utxo)> = tx
            .outputs
            .iter()
            .enumerate()
            .map(|(i, o)| {
                (
                    OutPoint { txid, index: i as u32 },
                    Utxo { address: o.address, amount: o.amount, height, coinbase: false },
                )
            })
            .collect();
        // una salida nueva no puede pisar otra existente (salvo que sea una de las que se gastan)
        for (op, _) in &new {
            if self.map.contains_key(op) && !spent.iter().any(|(s, _)| s == op) {
                return Err(UtxoError::DuplicateOutput(*op));
            }
        }

        // todo validado: mutar
        for (op, _) in &spent {
            self.map.remove(op);
        }
        let mut undo = Undo { spent, created: vec![] };
        for (op, u) in new {
            self.map.insert(op, u);
            undo.created.push(op);
        }
        let fee = (total_in - total_out) as u64; // ≤ suma de entradas, que cabe en el suministro máximo
        Ok((fee, undo))
    }

    /// Deshace una operación (en orden inverso al de aplicación).
    pub fn revert(&mut self, undo: Undo) {
        for op in &undo.created {
            self.map.remove(op);
        }
        for (op, u) in undo.spent {
            self.map.insert(op, u);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519::Keypair;
    use crate::tx::TxOut;

    const CHAIN: Hash32 = [0xaa; 32];

    fn kp(n: u8) -> Keypair {
        Keypair::from_seed([n; 32])
    }
    fn addr_of(k: &Keypair) -> Address {
        address_from_public_key(&k.public_key())
    }

    /// Conjunto con un coinbase de `amount` para `owner` en la altura 1.
    fn funded(owner: &Keypair, amount: u64) -> (UtxoSet, OutPoint) {
        let mut s = UtxoSet::new();
        let txid = [0x11; 32];
        s.apply_coinbase(txid, 1, &[(addr_of(owner), amount)]).unwrap();
        (s, OutPoint { txid, index: 0 })
    }

    const MATURE: u64 = 1 + COINBASE_MATURITY;

    #[test]
    fn spend_pays_fee_and_moves_value() {
        let (alice, bob) = (kp(1), kp(2));
        let (mut s, op) = funded(&alice, 1000);
        let tx = Transaction::build_signed(
            &[(op, &alice)],
            vec![TxOut { address: addr_of(&bob), amount: 600 }, TxOut { address: addr_of(&alice), amount: 350 }],
            &CHAIN,
        )
        .unwrap();
        let (fee, _undo) = s.apply_tx(&tx, MATURE, &CHAIN).unwrap();
        assert_eq!(fee, 50);
        assert!(s.get(&op).is_none());
        assert_eq!(s.balance_of(&addr_of(&bob)), 600);
        assert_eq!(s.balance_of(&addr_of(&alice)), 350);
        // lo que queda en el conjunto + la comisión = lo que había
        assert_eq!(s.total_amount() + fee as u128, 1000);
    }

    #[test]
    fn double_spend_is_rejected() {
        let (alice, bob, carol) = (kp(1), kp(2), kp(3));
        let (mut s, op) = funded(&alice, 1000);
        let to_bob = Transaction::build_signed(&[(op, &alice)], vec![TxOut { address: addr_of(&bob), amount: 900 }], &CHAIN).unwrap();
        let to_carol = Transaction::build_signed(&[(op, &alice)], vec![TxOut { address: addr_of(&carol), amount: 900 }], &CHAIN).unwrap();
        s.apply_tx(&to_bob, MATURE, &CHAIN).unwrap();
        assert_eq!(s.apply_tx(&to_carol, MATURE, &CHAIN), Err(UtxoError::MissingInput(0)));
        // repetir la misma transacción también es doble gasto
        assert_eq!(s.apply_tx(&to_bob, MATURE, &CHAIN), Err(UtxoError::MissingInput(0)));
        assert_eq!(s.balance_of(&addr_of(&carol)), 0);
    }

    #[test]
    fn only_the_owner_can_spend() {
        let (alice, mallory, bob) = (kp(1), kp(66), kp(2));
        let (mut s, op) = funded(&alice, 1000);
        // Mallory firma correctamente con su propia clave, pero el UTXO no es suyo
        let tx = Transaction::build_signed(&[(op, &mallory)], vec![TxOut { address: addr_of(&bob), amount: 1000 }], &CHAIN).unwrap();
        assert_eq!(s.apply_tx(&tx, MATURE, &CHAIN), Err(UtxoError::WrongOwner(0)));
        assert_eq!(s.balance_of(&addr_of(&alice)), 1000);
    }

    #[test]
    fn outputs_cannot_exceed_inputs() {
        let (alice, bob) = (kp(1), kp(2));
        let (mut s, op) = funded(&alice, 1000);
        let tx = Transaction::build_signed(&[(op, &alice)], vec![TxOut { address: addr_of(&bob), amount: 1001 }], &CHAIN).unwrap();
        assert_eq!(
            s.apply_tx(&tx, MATURE, &CHAIN),
            Err(UtxoError::OutputsExceedInputs { inputs: 1000, outputs: 1001 })
        );
        // exactamente igual (comisión 0) sí se puede
        let ok = Transaction::build_signed(&[(op, &alice)], vec![TxOut { address: addr_of(&bob), amount: 1000 }], &CHAIN).unwrap();
        assert_eq!(s.apply_tx(&ok, MATURE, &CHAIN).unwrap().0, 0);
    }

    #[test]
    fn coinbase_maturity() {
        let (alice, bob) = (kp(1), kp(2));
        let (mut s, op) = funded(&alice, 1000);
        let tx = Transaction::build_signed(&[(op, &alice)], vec![TxOut { address: addr_of(&bob), amount: 1000 }], &CHAIN).unwrap();
        assert_eq!(s.apply_tx(&tx, MATURE - 1, &CHAIN), Err(UtxoError::ImmatureCoinbase(0)));
        assert_eq!(s.apply_tx(&tx, 1, &CHAIN), Err(UtxoError::ImmatureCoinbase(0)));
        assert!(s.apply_tx(&tx, MATURE, &CHAIN).is_ok());
        // el dinero recibido en una transacción normal se puede gastar en el mismo bloque siguiente
        let bob_op = OutPoint { txid: tx.txid(), index: 0 };
        let carol = kp(3);
        let t2 = Transaction::build_signed(&[(bob_op, &kp(2))], vec![TxOut { address: addr_of(&carol), amount: 1000 }], &CHAIN).unwrap();
        assert!(s.apply_tx(&t2, MATURE, &CHAIN).is_ok());
    }

    #[test]
    fn failed_operations_leave_the_set_untouched() {
        let (alice, bob) = (kp(1), kp(2));
        let (mut s, op) = funded(&alice, 1000);
        let before = s.total_amount();
        // dos entradas, la segunda no existe: no debe consumirse la primera
        let ghost = OutPoint { txid: [0x99; 32], index: 3 };
        let tx = Transaction::build_signed(&[(op, &alice), (ghost, &alice)], vec![TxOut { address: addr_of(&bob), amount: 10 }], &CHAIN).unwrap();
        assert_eq!(s.apply_tx(&tx, MATURE, &CHAIN), Err(UtxoError::MissingInput(1)));
        assert_eq!(s.total_amount(), before);
        assert!(s.get(&op).is_some());
        // firma inválida
        let mut bad = Transaction::build_signed(&[(op, &alice)], vec![TxOut { address: addr_of(&bob), amount: 10 }], &CHAIN).unwrap();
        bad.inputs[0].signature[0] ^= 1;
        assert_eq!(s.apply_tx(&bad, MATURE, &CHAIN), Err(UtxoError::Tx(TxError::BadSignature(0))));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn revert_restores_everything_in_reverse_order() {
        let (alice, bob, carol) = (kp(1), kp(2), kp(3));
        let (mut s, op) = funded(&alice, 1000);
        let snapshot = |s: &UtxoSet| {
            let mut v: Vec<_> = s.map.iter().map(|(k, u)| (k.txid, k.index, u.amount, u.height)).collect();
            v.sort();
            v
        };
        let s0 = snapshot(&s);
        let t1 = Transaction::build_signed(&[(op, &alice)], vec![TxOut { address: addr_of(&bob), amount: 900 }], &CHAIN).unwrap();
        let (_, u1) = s.apply_tx(&t1, MATURE, &CHAIN).unwrap();
        let s1 = snapshot(&s);
        let op2 = OutPoint { txid: t1.txid(), index: 0 };
        let t2 = Transaction::build_signed(&[(op2, &bob)], vec![TxOut { address: addr_of(&carol), amount: 800 }], &CHAIN).unwrap();
        let (_, u2) = s.apply_tx(&t2, MATURE + 1, &CHAIN).unwrap();
        assert_ne!(snapshot(&s), s1);
        s.revert(u2);
        assert_eq!(snapshot(&s), s1);
        s.revert(u1);
        assert_eq!(snapshot(&s), s0);
        // y se puede volver a aplicar
        assert!(s.apply_tx(&t1, MATURE, &CHAIN).is_ok());
    }

    #[test]
    fn coinbase_outputs_split_and_duplicates() {
        let mut s = UtxoSet::new();
        let (a, b) = (Address([1; 32]), Address([2; 32]));
        let u = s.apply_coinbase([5; 32], 7, &[(a, 600), (b, 400), (a, 0)]).unwrap();
        assert_eq!(s.len(), 2); // la salida de monto 0 no crea UTXO
        assert_eq!(s.total_amount(), 1000);
        assert_eq!(s.apply_coinbase([5; 32], 8, &[(a, 1)]), Err(UtxoError::DuplicateOutput(OutPoint { txid: [5; 32], index: 0 })));
        assert_eq!(s.len(), 2);
        s.revert(u);
        assert!(s.is_empty());
    }

    #[test]
    fn money_is_conserved_over_a_random_walk() {
        // 6 cuentas se pasan dinero al azar (determinista): la suma del conjunto más las
        // comisiones acumuladas es siempre la emisión inicial.
        let keys: Vec<Keypair> = (1..=6).map(kp).collect();
        let mut s = UtxoSet::new();
        let mut total_issued = 0u128;
        let mut owned: Vec<(OutPoint, usize, u64)> = vec![]; // (outpoint, dueño, monto)
        for (i, k) in keys.iter().enumerate() {
            let txid = [0x40 + i as u8; 32];
            s.apply_coinbase(txid, 1, &[(addr_of(k), 10_000)]).unwrap();
            owned.push((OutPoint { txid, index: 0 }, i, 10_000));
            total_issued += 10_000;
        }
        let mut fees = 0u128;
        let mut x = 99u32;
        let mut rnd = |n: u32| {
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            (x >> 8) % n
        };
        for step in 0..60u64 {
            let pick = rnd(owned.len() as u32) as usize;
            let (op, owner, amount) = owned.remove(pick);
            let dest = rnd(6) as usize;
            let fee = (rnd(3) as u64).min(amount - 1);
            let send = amount - fee;
            let tx = Transaction::build_signed(
                &[(op, &keys[owner])],
                vec![TxOut { address: addr_of(&keys[dest]), amount: send }],
                &CHAIN,
            )
            .unwrap();
            let (f, _) = s.apply_tx(&tx, MATURE + step, &CHAIN).unwrap();
            assert_eq!(f, fee);
            fees += f as u128;
            owned.push((OutPoint { txid: tx.txid(), index: 0 }, dest, send));
            assert_eq!(s.total_amount() + fees, total_issued, "paso {step}");
        }
    }
}
