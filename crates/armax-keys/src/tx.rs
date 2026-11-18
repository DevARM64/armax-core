//! Transacciones (modelo UTXO, un solo firmante por entrada).
//!
//! Formato canónico (todo little-endian):
//! ```text
//!   version u8 | n_in u8 | n_in × ( txid 32 | index u32 | clave pública 32 | firma 64 )
//!              | n_out u8 | n_out × ( dirección 32 | monto u64 )
//! ```
//! * `txid` = SHA-256("ARMAX-TXID-v0" ‖ cuerpo) donde el cuerpo contiene versión, entradas
//!   (solo `txid` e `index`) y salidas: **no incluye claves ni firmas**, así que nadie puede
//!   cambiar el id de una transacción ya firmada.
//! * `full_id` incluye claves y firmas: es la hoja que irá en la raíz de Merkle del bloque.
//! * Cada entrada firma el mismo `sighash` = SHA-256("ARMAX-SIGHASH-v0" ‖ chain_id ‖ cuerpo), que
//!   cubre todas las entradas y todas las salidas (equivalente a SIGHASH_ALL). `chain_id` (el id
//!   del génesis) evita repetir la misma transacción en otra cadena con los mismos UTXO.
//! * La comisión es implícita: suma de entradas − suma de salidas (se comprueba contra el
//!   conjunto de UTXO en `utxo.rs`).
//!
//! Límite conocido: la firma no cubre los montos de los UTXO gastados; una cartera de hardware que
//! quiera mostrar la comisión sin confiar en el equipo tendría que recibirlos aparte.

use core::fmt;

use armax_chain::emission::NOMINAL_MAX_SUPPLY;
use armax_chain::Address;
use armax_vm::sha256::sha256_cat;

use crate::address::address_from_public_key;
use crate::ed25519::{self, Keypair};

pub const TX_VERSION: u8 = 1;
pub const MAX_TX_INPUTS: usize = 64;
pub const MAX_TX_OUTPUTS: usize = 64;

pub type Hash32 = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OutPoint {
    pub txid: Hash32,
    pub index: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxIn {
    pub prev: OutPoint,
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxOut {
    pub address: Address,
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TxError {
    BadVersion(u8),
    /// Cantidad de entradas fuera de 1..=64.
    BadInputCount(usize),
    /// Cantidad de salidas fuera de 1..=64.
    BadOutputCount(usize),
    ZeroAmount(usize),
    /// Una salida o la suma de salidas supera el suministro máximo nominal.
    AmountTooLarge,
    DuplicateInput(usize),
    BadSignature(usize),
    /// Bytes de más, de menos o campos mal formados al leer.
    Malformed(&'static str),
    /// `sign_all` recibió un número de llaves distinto al de entradas.
    KeyCountMismatch,
}

impl fmt::Display for TxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for TxError {}

/// Transacción cuyas reglas sin estado y firmas ya se comprobaron. Solo se puede obtener con
/// `Transaction::verify` o `verify_batch`, de modo que `UtxoSet::apply_verified` nunca recibe una
/// transacción sin verificar.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedTx<'a> {
    tx: &'a Transaction,
}

impl<'a> VerifiedTx<'a> {
    pub fn tx(&self) -> &'a Transaction {
        self.tx
    }
}

/// Verifica un lote de transacciones repartiéndolas entre `threads` hilos. Devuelve el índice y el
/// error de la **primera** que falle (el resultado no depende del número de hilos).
pub fn verify_batch<'a>(
    txs: &'a [Transaction],
    chain_id: &Hash32,
    threads: usize,
) -> Result<Vec<VerifiedTx<'a>>, (usize, TxError)> {
    let threads = threads.clamp(1, txs.len().max(1));
    if threads == 1 {
        return txs
            .iter()
            .enumerate()
            .map(|(i, t)| t.verify(chain_id).map_err(|e| (i, e)))
            .collect();
    }
    let chunk = txs.len().div_ceil(threads);
    let results: Vec<Result<Vec<VerifiedTx<'a>>, (usize, TxError)>> = std::thread::scope(|s| {
        let handles: Vec<_> = txs
            .chunks(chunk)
            .enumerate()
            .map(|(c, part)| {
                s.spawn(move || {
                    part.iter()
                        .enumerate()
                        .map(|(i, t)| t.verify(chain_id).map_err(|e| (c * chunk + i, e)))
                        .collect::<Result<Vec<_>, _>>()
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().expect("hilo de verificación")).collect()
    });
    let mut out = Vec::with_capacity(txs.len());
    for r in results {
        out.extend(r?); // los fragmentos están en orden: el primer error es el de menor índice
    }
    Ok(out)
}

impl Transaction {
    /// Comprueba las reglas sin estado y las firmas, y entrega la transacción verificada.
    pub fn verify(&self, chain_id: &Hash32) -> Result<VerifiedTx<'_>, TxError> {
        self.check(chain_id)?;
        Ok(VerifiedTx { tx: self })
    }

    /// Cuerpo sin claves ni firmas (lo que determina el `txid` y el `sighash`).
    fn body_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(2 + self.inputs.len() * 36 + self.outputs.len() * 40);
        b.push(TX_VERSION);
        b.push(self.inputs.len() as u8);
        for i in &self.inputs {
            b.extend_from_slice(&i.prev.txid);
            b.extend_from_slice(&i.prev.index.to_le_bytes());
        }
        b.push(self.outputs.len() as u8);
        for o in &self.outputs {
            b.extend_from_slice(&o.address.0);
            b.extend_from_slice(&o.amount.to_le_bytes());
        }
        b
    }

    pub fn txid(&self) -> Hash32 {
        sha256_cat(&[b"ARMAX-TXID-v0", &self.body_bytes()])
    }

    pub fn sighash(&self, chain_id: &Hash32) -> Hash32 {
        sha256_cat(&[b"ARMAX-SIGHASH-v0", chain_id, &self.body_bytes()])
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        assert!(self.inputs.len() <= MAX_TX_INPUTS && self.outputs.len() <= MAX_TX_OUTPUTS);
        let mut b = Vec::with_capacity(2 + self.inputs.len() * 132 + self.outputs.len() * 40);
        b.push(TX_VERSION);
        b.push(self.inputs.len() as u8);
        for i in &self.inputs {
            b.extend_from_slice(&i.prev.txid);
            b.extend_from_slice(&i.prev.index.to_le_bytes());
            b.extend_from_slice(&i.public_key);
            b.extend_from_slice(&i.signature);
        }
        b.push(self.outputs.len() as u8);
        for o in &self.outputs {
            b.extend_from_slice(&o.address.0);
            b.extend_from_slice(&o.amount.to_le_bytes());
        }
        b
    }

    pub fn full_id(&self) -> Hash32 {
        sha256_cat(&[b"ARMAX-TXFULL-v0", &self.to_bytes()])
    }

    /// Lectura estricta: sin bytes sobrantes y con las cantidades dentro de los límites.
    pub fn from_bytes(data: &[u8]) -> Result<Transaction, TxError> {
        let mut pos = 0usize;
        let mut take = |n: usize| -> Result<&[u8], TxError> {
            let end = pos.checked_add(n).ok_or(TxError::Malformed("desbordamiento"))?;
            let s = data.get(pos..end).ok_or(TxError::Malformed("datos cortos"))?;
            pos = end;
            Ok(s)
        };
        let version = take(1)?[0];
        if version != TX_VERSION {
            return Err(TxError::BadVersion(version));
        }
        let n_in = take(1)?[0] as usize;
        if !(1..=MAX_TX_INPUTS).contains(&n_in) {
            return Err(TxError::BadInputCount(n_in));
        }
        let mut inputs = Vec::with_capacity(n_in);
        for _ in 0..n_in {
            let raw = take(132)?;
            inputs.push(TxIn {
                prev: OutPoint {
                    txid: raw[..32].try_into().unwrap(),
                    index: u32::from_le_bytes(raw[32..36].try_into().unwrap()),
                },
                public_key: raw[36..68].try_into().unwrap(),
                signature: raw[68..132].try_into().unwrap(),
            });
        }
        let n_out = take(1)?[0] as usize;
        if !(1..=MAX_TX_OUTPUTS).contains(&n_out) {
            return Err(TxError::BadOutputCount(n_out));
        }
        let mut outputs = Vec::with_capacity(n_out);
        for _ in 0..n_out {
            let raw = take(40)?;
            outputs.push(TxOut {
                address: Address(raw[..32].try_into().unwrap()),
                amount: u64::from_le_bytes(raw[32..40].try_into().unwrap()),
            });
        }
        if pos != data.len() {
            return Err(TxError::Malformed("bytes sobrantes"));
        }
        Ok(Transaction { inputs, outputs })
    }

    /// Suma de las salidas (en `u128`, sin desbordar).
    pub fn output_total(&self) -> u128 {
        self.outputs.iter().map(|o| o.amount as u128).sum()
    }

    /// Reglas que no dependen del estado de la cadena: tamaños, montos, entradas repetidas y
    /// firmas. Que las entradas existan y pertenezcan a quien firma lo comprueba `UtxoSet`.
    pub fn check(&self, chain_id: &Hash32) -> Result<(), TxError> {
        if !(1..=MAX_TX_INPUTS).contains(&self.inputs.len()) {
            return Err(TxError::BadInputCount(self.inputs.len()));
        }
        if !(1..=MAX_TX_OUTPUTS).contains(&self.outputs.len()) {
            return Err(TxError::BadOutputCount(self.outputs.len()));
        }
        for (i, o) in self.outputs.iter().enumerate() {
            if o.amount == 0 {
                return Err(TxError::ZeroAmount(i));
            }
            if o.amount > NOMINAL_MAX_SUPPLY {
                return Err(TxError::AmountTooLarge);
            }
        }
        if self.output_total() > NOMINAL_MAX_SUPPLY as u128 {
            return Err(TxError::AmountTooLarge);
        }
        let mut seen = std::collections::HashSet::with_capacity(self.inputs.len());
        for (i, inp) in self.inputs.iter().enumerate() {
            if !seen.insert(inp.prev) {
                return Err(TxError::DuplicateInput(i));
            }
        }
        let h = self.sighash(chain_id);
        for (i, inp) in self.inputs.iter().enumerate() {
            if !ed25519::verify(&inp.public_key, &h, &inp.signature) {
                return Err(TxError::BadSignature(i));
            }
        }
        Ok(())
    }

    /// Construye y firma una transacción: cada entrada con su llave.
    pub fn build_signed(
        inputs: &[(OutPoint, &Keypair)],
        outputs: Vec<TxOut>,
        chain_id: &Hash32,
    ) -> Result<Transaction, TxError> {
        let mut tx = Transaction {
            inputs: inputs
                .iter()
                .map(|(prev, kp)| TxIn { prev: *prev, public_key: kp.public_key(), signature: [0u8; 64] })
                .collect(),
            outputs,
        };
        if !(1..=MAX_TX_INPUTS).contains(&tx.inputs.len()) {
            return Err(TxError::BadInputCount(tx.inputs.len()));
        }
        if !(1..=MAX_TX_OUTPUTS).contains(&tx.outputs.len()) {
            return Err(TxError::BadOutputCount(tx.outputs.len()));
        }
        let h = tx.sighash(chain_id);
        for (inp, (_, kp)) in tx.inputs.iter_mut().zip(inputs) {
            inp.signature = kp.sign(&h);
        }
        Ok(tx)
    }

    /// Dirección que debe tener el UTXO que gasta la entrada `i`.
    pub fn input_address(&self, i: usize) -> Address {
        address_from_public_key(&self.inputs[i].public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHAIN: Hash32 = [0xc0; 32];

    fn kp(n: u8) -> Keypair {
        Keypair::from_seed([n; 32])
    }
    fn op(n: u8, i: u32) -> OutPoint {
        OutPoint { txid: [n; 32], index: i }
    }
    fn to(n: u8, amount: u64) -> TxOut {
        TxOut { address: Address([n; 32]), amount }
    }

    #[test]
    fn signed_transaction_checks_out() {
        let (a, b) = (kp(1), kp(2));
        let tx = Transaction::build_signed(&[(op(7, 0), &a), (op(8, 1), &b)], vec![to(9, 500), to(10, 250)], &CHAIN)
            .unwrap();
        assert_eq!(tx.check(&CHAIN), Ok(()));
        assert_eq!(tx.input_address(0), address_from_public_key(&a.public_key()));
        // otra cadena: la firma no vale
        assert_eq!(tx.check(&[0u8; 32]), Err(TxError::BadSignature(0)));
    }

    #[test]
    fn tampering_with_any_field_breaks_the_signature() {
        let a = kp(1);
        let tx = Transaction::build_signed(&[(op(7, 0), &a)], vec![to(9, 500), to(10, 250)], &CHAIN).unwrap();
        let mut t = tx.clone();
        t.outputs[0].amount += 1;
        assert_eq!(t.check(&CHAIN), Err(TxError::BadSignature(0)));
        let mut t = tx.clone();
        t.outputs[1].address.0[0] ^= 1;
        assert_eq!(t.check(&CHAIN), Err(TxError::BadSignature(0)));
        let mut t = tx.clone();
        t.inputs[0].prev.index = 1;
        assert_eq!(t.check(&CHAIN), Err(TxError::BadSignature(0)));
        let mut t = tx.clone();
        t.outputs.reverse();
        assert_eq!(t.check(&CHAIN), Err(TxError::BadSignature(0)));
        let mut t = tx.clone();
        t.inputs[0].signature[3] ^= 1;
        assert_eq!(t.check(&CHAIN), Err(TxError::BadSignature(0)));
        // firmar con otra llave pero declarar la clave pública original
        let mut t = tx.clone();
        t.inputs[0].signature = kp(2).sign(&t.sighash(&CHAIN));
        assert_eq!(t.check(&CHAIN), Err(TxError::BadSignature(0)));
    }

    #[test]
    fn txid_ignores_witness_but_full_id_does_not() {
        let a = kp(1);
        let tx = Transaction::build_signed(&[(op(7, 0), &a)], vec![to(9, 500)], &CHAIN).unwrap();
        let mut t = tx.clone();
        t.inputs[0].signature[0] ^= 0xff;
        assert_eq!(t.txid(), tx.txid());
        assert_ne!(t.full_id(), tx.full_id());
        let mut t = tx.clone();
        t.outputs[0].amount += 1;
        assert_ne!(t.txid(), tx.txid());
        // el txid no depende de la cadena; el sighash sí
        assert_ne!(tx.sighash(&CHAIN), tx.sighash(&[1u8; 32]));
    }

    #[test]
    fn stateless_rules() {
        let a = kp(1);
        let ok = |o: Vec<TxOut>| Transaction::build_signed(&[(op(7, 0), &a)], o, &CHAIN);
        assert_eq!(ok(vec![]).unwrap_err(), TxError::BadOutputCount(0));
        assert_eq!(ok((0..65).map(|i| to(i as u8, 1)).collect()).unwrap_err(), TxError::BadOutputCount(65));
        assert_eq!(ok(vec![to(1, 5), to(2, 0)]).unwrap().check(&CHAIN), Err(TxError::ZeroAmount(1)));
        assert_eq!(ok(vec![to(1, NOMINAL_MAX_SUPPLY + 1)]).unwrap().check(&CHAIN), Err(TxError::AmountTooLarge));
        // la suma de dos salidas válidas por separado supera el máximo (y u64 no desborda gracias a u128)
        assert_eq!(
            ok(vec![to(1, NOMINAL_MAX_SUPPLY), to(2, 1)]).unwrap().check(&CHAIN),
            Err(TxError::AmountTooLarge)
        );
        assert_eq!(ok(vec![to(1, u64::MAX), to(2, u64::MAX)]).unwrap().check(&CHAIN), Err(TxError::AmountTooLarge));
        // entrada repetida
        let dup = Transaction::build_signed(&[(op(7, 0), &a), (op(7, 0), &a)], vec![to(1, 5)], &CHAIN).unwrap();
        assert_eq!(dup.check(&CHAIN), Err(TxError::DuplicateInput(1)));
        assert_eq!(
            Transaction::build_signed(&[], vec![to(1, 5)], &CHAIN).unwrap_err(),
            TxError::BadInputCount(0)
        );
    }

    #[test]
    fn batch_verification_is_deterministic_for_any_thread_count() {
        let keys: Vec<Keypair> = (1..=5).map(kp).collect();
        let mut txs: Vec<Transaction> = (0..23u8)
            .map(|i| {
                Transaction::build_signed(
                    &[(op(i, 0), &keys[i as usize % 5])],
                    vec![to(i, 10 + i as u64)],
                    &CHAIN,
                )
                .unwrap()
            })
            .collect();
        for threads in [0, 1, 2, 3, 7, 23, 64] {
            let ok = verify_batch(&txs, &CHAIN, threads).unwrap();
            assert_eq!(ok.len(), 23);
            assert!(ok.iter().zip(&txs).all(|(v, t)| std::ptr::eq(v.tx(), t)), "orden conservado (hilos {threads})");
        }
        // dos fallos: se informa del de menor índice, con cualquier número de hilos
        txs[17].outputs[0].amount += 1;
        txs[9].inputs[0].signature[0] ^= 1;
        for threads in [1, 2, 3, 7, 23] {
            assert_eq!(verify_batch(&txs, &CHAIN, threads).unwrap_err(), (9, TxError::BadSignature(0)), "hilos {threads}");
        }
        assert_eq!(verify_batch(&[], &CHAIN, 4).unwrap().len(), 0);
    }

    #[test]
    fn serialization_roundtrip_and_strict_parsing() {
        let (a, b) = (kp(1), kp(2));
        let tx = Transaction::build_signed(&[(op(7, 0), &a), (op(8, 1), &b)], vec![to(9, 500), to(10, 250)], &CHAIN)
            .unwrap();
        let bytes = tx.to_bytes();
        assert_eq!(bytes.len(), 1 + 1 + 2 * 132 + 1 + 2 * 40); // 347
        assert_eq!(Transaction::from_bytes(&bytes), Ok(tx.clone()));
        // bytes de más / de menos / versión / contadores
        let mut more = bytes.clone();
        more.push(0);
        assert_eq!(Transaction::from_bytes(&more), Err(TxError::Malformed("bytes sobrantes")));
        assert!(Transaction::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        let mut v = bytes.clone();
        v[0] = 2;
        assert_eq!(Transaction::from_bytes(&v), Err(TxError::BadVersion(2)));
        let mut c = bytes.clone();
        c[1] = 0;
        assert_eq!(Transaction::from_bytes(&c), Err(TxError::BadInputCount(0)));
        c[1] = 65;
        assert_eq!(Transaction::from_bytes(&c), Err(TxError::BadInputCount(65)));
        assert!(Transaction::from_bytes(&[]).is_err());
        // basura aleatoria nunca provoca pánico
        let mut x = 0x1234_5678u32;
        for len in 0..300 {
            let junk: Vec<u8> = (0..len)
                .map(|_| {
                    x = x.wrapping_mul(1664525).wrapping_add(1013904223);
                    (x >> 24) as u8
                })
                .collect();
            let _ = Transaction::from_bytes(&junk);
        }
    }
}
