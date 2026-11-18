//! Minero de referencia de un solo hilo: busca un nonce para una cabecera.
//!
//! No aplica el límite de 4,000 H/s ni el control térmico: eso es responsabilidad de
//! `armax-thermal` y de la capa del nodo, que deben llamar a `mine` en tandas pequeñas
//! (`max_attempts`) y dormir/pausar entre ellas.

use std::sync::atomic::{AtomicBool, Ordering};

use armax_vm::{pow_hash, Aes, OpTable};

use crate::consensus::{target_for, Consensus};
use crate::header::{Header, NONCE_OFFSET};
use crate::u256::U256;

/// Prueba nonces `start_nonce, start_nonce+1, ...` hasta `max_attempts` intentos.
/// Devuelve `(nonce, digest)` si encuentra uno válido; `None` si se agota o `stop` se activa.
pub fn mine<B: Aes>(
    c: &Consensus,
    table: &OpTable,
    header: &Header,
    scratch: &mut [u8],
    start_nonce: u64,
    max_attempts: u64,
    stop: &AtomicBool,
) -> Option<(u64, [u8; 32])> {
    let target = target_for(header.difficulty);
    let mut bytes = header.to_bytes();
    for i in 0..max_attempts {
        if stop.load(Ordering::Relaxed) {
            return None;
        }
        let nonce = start_nonce.wrapping_add(i);
        bytes[NONCE_OFFSET..].copy_from_slice(&nonce.to_le_bytes());
        let digest = pow_hash::<B>(&c.vm, table, &bytes, scratch);
        if U256::from_be_bytes(&digest) <= target {
            return Some((nonce, digest));
        }
    }
    None
}
