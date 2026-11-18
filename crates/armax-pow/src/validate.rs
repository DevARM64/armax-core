//! Validación de cabeceras: primero las reglas baratas, después el PoW (que cuesta una
//! ejecución completa de la VM con 384 MiB). Un bloque basura nunca llega a la VM.

use core::fmt;

use armax_vm::{pow_hash, Aes, OpTable, Params};

use crate::consensus::{pow_limit, HEADER_VERSION, MAX_FUTURE_SECS, MTP_WINDOW};
use crate::header::{BlockHeader, Hash32};
use crate::lwma::{next_target, WindowEntry};
use crate::u256::U256;

#[derive(Debug, PartialEq, Eq)]
pub enum HeaderError {
    NoParent,
    BadVersion(u32),
    BadHeight { expected: u64, got: u64 },
    BadPrevHash,
    TargetOutOfRange,
    TargetMismatch { expected: U256, got: U256 },
    TimestampNotAfterMedian { median: u64, got: u64 },
    TimestampTooFarInFuture { limit: u64, got: u64 },
    InsufficientWork,
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for HeaderError {}

/// Datos del padre necesarios para validar a su hijo.
#[derive(Clone, Copy, Debug)]
pub struct ParentInfo {
    pub height: u64,
    pub id: Hash32,
}

/// Mediana de los últimos `MTP_WINDOW` timestamps de la ventana.
pub fn median_time_past(window: &[WindowEntry]) -> u64 {
    let take = window.len().min(MTP_WINDOW);
    let mut ts: Vec<u64> = window[window.len() - take..].iter().map(|e| e.0).collect();
    ts.sort_unstable();
    ts[ts.len() / 2]
}

/// `digest ≤ target`, ambos como números de 256 bits big-endian.
pub fn meets_target(digest: &[u8; 32], target: &U256) -> bool {
    U256::from_be_bytes(digest) <= *target
}

/// Reglas baratas (sin PoW). `window` termina en el padre; `now` es el reloj local (s Unix).
pub fn validate_header_cheap(
    h: &BlockHeader,
    parent: &ParentInfo,
    window: &[WindowEntry],
    now: u64,
) -> Result<(), HeaderError> {
    if window.is_empty() {
        return Err(HeaderError::NoParent);
    }
    if h.version != HEADER_VERSION {
        return Err(HeaderError::BadVersion(h.version));
    }
    if h.height != parent.height + 1 {
        return Err(HeaderError::BadHeight { expected: parent.height + 1, got: h.height });
    }
    if h.prev_hash != parent.id {
        return Err(HeaderError::BadPrevHash);
    }
    if h.target.is_zero() || h.target > pow_limit() {
        return Err(HeaderError::TargetOutOfRange);
    }
    let expected = next_target(window);
    if h.target != expected {
        return Err(HeaderError::TargetMismatch { expected, got: h.target });
    }
    let median = median_time_past(window);
    if h.timestamp <= median {
        return Err(HeaderError::TimestampNotAfterMedian { median, got: h.timestamp });
    }
    let limit = now.saturating_add(MAX_FUTURE_SECS);
    if h.timestamp > limit {
        return Err(HeaderError::TimestampTooFarInFuture { limit, got: h.timestamp });
    }
    Ok(())
}

/// Comprueba el PoW de una cabecera (caro). Devuelve el digest si cumple el target declarado.
pub fn verify_pow<B: Aes>(
    h: &BlockHeader,
    params: &Params,
    table: &OpTable,
    scratch: &mut [u8],
) -> Result<[u8; 32], HeaderError> {
    let digest = pow_hash::<B>(params, table, &h.to_bytes(), scratch);
    if meets_target(&digest, &h.target) {
        Ok(digest)
    } else {
        Err(HeaderError::InsufficientWork)
    }
}

/// Como `verify_pow`, pero contra un `target` explícito en vez del de la cabecera. Lo usan los
/// shares de un pool: la misma cabecera y la misma VM, con un umbral más fácil que el del bloque.
pub fn verify_pow_at<B: Aes>(
    h: &BlockHeader,
    target: &U256,
    params: &Params,
    table: &OpTable,
    scratch: &mut [u8],
) -> Result<[u8; 32], HeaderError> {
    let digest = pow_hash::<B>(params, table, &h.to_bytes(), scratch);
    if meets_target(&digest, target) {
        Ok(digest)
    } else {
        Err(HeaderError::InsufficientWork)
    }
}

/// Validación completa: reglas baratas y, solo si pasan, el PoW.
pub fn validate_header<B: Aes>(
    h: &BlockHeader,
    parent: &ParentInfo,
    window: &[WindowEntry],
    now: u64,
    params: &Params,
    table: &OpTable,
    scratch: &mut [u8],
) -> Result<[u8; 32], HeaderError> {
    validate_header_cheap(h, parent, window, now)?;
    verify_pow::<B>(h, params, table, scratch)
}

/// Minero de referencia: prueba nonces consecutivos desde `start_nonce`.
/// `should_stop` se consulta antes de cada intento (aquí engancharán la capa térmica y
/// los cambios de bloque). Devuelve el nonce y el digest si encuentra solución.
pub fn mine<B: Aes>(
    template: &BlockHeader,
    params: &Params,
    table: &OpTable,
    scratch: &mut [u8],
    start_nonce: u64,
    max_attempts: u64,
    should_stop: &mut dyn FnMut() -> bool,
) -> Option<(u64, [u8; 32])> {
    mine_at::<B>(template, &template.target, params, table, scratch, start_nonce, max_attempts, should_stop)
}

/// Como `mine`, pero el umbral es `target` y no el de la cabecera. Un pool lo usa con un umbral
/// más fácil para hallar shares; el digest que cumple el target del bloque (más difícil) además es
/// un bloque válido.
#[allow(clippy::too_many_arguments)]
pub fn mine_at<B: Aes>(
    template: &BlockHeader,
    target: &U256,
    params: &Params,
    table: &OpTable,
    scratch: &mut [u8],
    start_nonce: u64,
    max_attempts: u64,
    should_stop: &mut dyn FnMut() -> bool,
) -> Option<(u64, [u8; 32])> {
    for i in 0..max_attempts {
        if should_stop() {
            return None;
        }
        let nonce = start_nonce.wrapping_add(i);
        let h = template.with_nonce(nonce);
        let digest = pow_hash::<B>(params, table, &h.to_bytes(), scratch);
        if meets_target(&digest, target) {
            return Some((nonce, digest));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{initial_target, LWMA_WINDOW, TARGET_BLOCK_TIME};
    use armax_vm::{Portable, Scratchpad};

    const NOW: u64 = 1_800_000_000;

    /// Cadena sintética con bloques cada T segundos terminando en `NOW - 30`.
    fn chain() -> (Vec<WindowEntry>, ParentInfo) {
        let t = initial_target();
        let n = LWMA_WINDOW + 1;
        let w: Vec<WindowEntry> = (0..n)
            .map(|i| (NOW - 30 - (n - 1 - i) as u64 * TARGET_BLOCK_TIME, t))
            .collect();
        (w, ParentInfo { height: 100, id: [7u8; 32] })
    }

    fn child(window: &[WindowEntry], parent: &ParentInfo) -> BlockHeader {
        BlockHeader {
            version: HEADER_VERSION,
            height: parent.height + 1,
            prev_hash: parent.id,
            merkle_root: [1u8; 32],
            timestamp: NOW,
            target: next_target(window),
            nonce: 0,
        }
    }

    #[test]
    fn accepts_well_formed_header() {
        let (w, p) = chain();
        assert_eq!(validate_header_cheap(&child(&w, &p), &p, &w, NOW), Ok(()));
    }

    #[test]
    fn rejects_each_rule() {
        let (w, p) = chain();
        let ok = child(&w, &p);

        let mut h = ok.clone();
        h.version = 9;
        assert_eq!(validate_header_cheap(&h, &p, &w, NOW), Err(HeaderError::BadVersion(9)));

        let mut h = ok.clone();
        h.height += 1;
        assert!(matches!(validate_header_cheap(&h, &p, &w, NOW), Err(HeaderError::BadHeight { .. })));

        let mut h = ok.clone();
        h.prev_hash[0] ^= 1;
        assert_eq!(validate_header_cheap(&h, &p, &w, NOW), Err(HeaderError::BadPrevHash));

        // El minero no puede elegir su propio target (aunque sea "más difícil").
        let mut h = ok.clone();
        h.target = h.target.shr(1);
        assert!(matches!(validate_header_cheap(&h, &p, &w, NOW), Err(HeaderError::TargetMismatch { .. })));

        let mut h = ok.clone();
        h.target = U256::ZERO;
        assert_eq!(validate_header_cheap(&h, &p, &w, NOW), Err(HeaderError::TargetOutOfRange));
        let mut h = ok.clone();
        h.target = U256::MAX;
        assert_eq!(validate_header_cheap(&h, &p, &w, NOW), Err(HeaderError::TargetOutOfRange));

        let median = median_time_past(&w);
        let mut h = ok.clone();
        h.timestamp = median;
        assert!(matches!(
            validate_header_cheap(&h, &p, &w, NOW),
            Err(HeaderError::TimestampNotAfterMedian { .. })
        ));

        let mut h = ok.clone();
        h.timestamp = NOW + MAX_FUTURE_SECS + 1;
        assert!(matches!(
            validate_header_cheap(&h, &p, &w, NOW),
            Err(HeaderError::TimestampTooFarInFuture { .. })
        ));
        // justo en el límite es válido
        let mut h = ok.clone();
        h.timestamp = NOW + MAX_FUTURE_SECS;
        assert_eq!(validate_header_cheap(&h, &p, &w, NOW), Ok(()));

        assert_eq!(validate_header_cheap(&ok, &p, &[], NOW), Err(HeaderError::NoParent));
    }

    #[test]
    fn median_time_past_is_robust_to_one_outlier() {
        let t = initial_target();
        let mut w: Vec<WindowEntry> = (0..20).map(|i| (1000 + i * 100, t)).collect();
        let before = median_time_past(&w);
        let last = w.len() - 1;
        w[last].0 = u64::MAX / 2; // un solo timestamp absurdo sustituye al máximo: la mediana no cambia
        assert_eq!(median_time_past(&w), before);
        assert!(median_time_past(&w) < 10_000);
    }

    #[test]
    fn target_comparison_boundary() {
        let mut digest = [0u8; 32];
        digest[31] = 5;
        assert!(meets_target(&digest, &U256::from_u64(5))); // igual cuenta
        assert!(!meets_target(&digest, &U256::from_u64(4)));
        // orden big-endian: el byte 0 es el más significativo
        let mut d2 = [0u8; 32];
        d2[0] = 1;
        assert!(!meets_target(&d2, &U256::from_u64(u64::MAX)));
        assert!(meets_target(&d2, &U256::pow2(248).unwrap()));
    }

    #[test]
    fn mining_and_verification_end_to_end() {
        // Parámetros reducidos (NO de consenso) y un target fácil: ~1 de cada 4 intentos.
        let params = Params::TEST;
        let table = OpTable::identity();
        let mut sp = Scratchpad::new(params.scratch_bytes).unwrap();

        let template = BlockHeader {
            version: HEADER_VERSION,
            height: 1,
            prev_hash: [3u8; 32],
            merkle_root: [4u8; 32],
            timestamp: NOW,
            target: U256::MAX.div_u64(4),
            nonce: 0,
        };

        let (nonce, digest) =
            mine::<Portable>(&template, &params, &table, sp.as_mut_slice(), 0, 500, &mut || false)
                .expect("con p=1/4, 500 intentos bastan con probabilidad 1-(3/4)^500");

        let solved = template.with_nonce(nonce);
        assert_eq!(verify_pow::<Portable>(&solved, &params, &table, sp.as_mut_slice()), Ok(digest));

        // Cambiar el nonce a uno que no cumple falla (buscamos uno que no cumpla).
        let bad = (nonce + 1..nonce + 200)
            .map(|n| template.with_nonce(n))
            .find(|h| verify_pow::<Portable>(h, &params, &table, sp.as_mut_slice()).is_err())
            .expect("alguno de 200 no cumple");
        assert_eq!(
            verify_pow::<Portable>(&bad, &params, &table, sp.as_mut_slice()),
            Err(HeaderError::InsufficientWork)
        );

        // Un target más estricto que el declarado por el minero invalida la misma solución.
        let mut stricter = solved.clone();
        stricter.target = U256::from_be_bytes(&digest).checked_sub(U256::ONE).unwrap_or(U256::ZERO);
        assert!(verify_pow::<Portable>(&stricter, &params, &table, sp.as_mut_slice()).is_err());

        // Otra tabla de época cambia el digest: la solución no vale entre épocas.
        let other_epoch = OpTable::for_epoch(&[9u8; 32]);
        let d2 = pow_hash::<Portable>(&params, &other_epoch, &solved.to_bytes(), sp.as_mut_slice());
        assert_ne!(d2, digest);
    }

    #[test]
    fn mining_respects_stop_signal() {
        let params = Params::TEST;
        let table = OpTable::identity();
        let mut sp = Scratchpad::new(params.scratch_bytes).unwrap();
        let template = BlockHeader {
            version: 1,
            height: 1,
            prev_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: NOW,
            target: U256::ONE, // imposible en la práctica
            nonce: 0,
        };
        let mut calls = 0;
        let r = mine::<Portable>(&template, &params, &table, sp.as_mut_slice(), 0, 1_000_000, &mut || {
            calls += 1;
            calls > 3
        });
        assert!(r.is_none());
        assert_eq!(calls, 4);
    }

    #[test]
    fn cheap_rules_run_before_the_expensive_pow() {
        // Un hijo con prev_hash incorrecto debe fallar sin tocar el scratchpad: pasamos un
        // buffer de tamaño inválido, que haría `pow_hash` entrar en pánico si se llegara a él.
        let (w, p) = chain();
        let mut h = child(&w, &p);
        h.prev_hash = [0u8; 32];
        let mut wrong_size = vec![0u8; 10];
        let r = validate_header::<Portable>(
            &h,
            &p,
            &w,
            NOW,
            &Params::TEST,
            &OpTable::identity(),
            &mut wrong_size,
        );
        assert_eq!(r, Err(HeaderError::BadPrevHash));
    }
}
