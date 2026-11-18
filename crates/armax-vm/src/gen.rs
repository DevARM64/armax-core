//! Generador de flujo AES de 4 carriles (estilo `AesGenerator1R` de RandomX).
//!
//! Se usa para (a) rellenar el scratchpad, (b) generar el programa de la VM y
//! (c) inicializar los registros. Es una función **secuencial**: la línea `k`
//! depende de la `k-1`, así que no se puede calcular una línea suelta sin
//! recorrer la cadena. Esto es lo que impide sustituir RAM por cómputo
//! "bajo demanda" (el scratchpad no es un modo contador).

use core::marker::PhantomData;

use crate::aes::{Aes, State};
use crate::isa::{Instr, INSTR_BYTES};
use crate::sha256::sha256_cat;

pub const DOM_PROGRAM: u8 = 1;
pub const DOM_SCRATCH: u8 = 2;
pub const DOM_REGS: u8 = 3;

pub struct AesGen<B: Aes> {
    st: [State; 4],
    key: [State; 4],
    _b: PhantomData<B>,
}

impl<B: Aes> AesGen<B> {
    /// Estado y claves iniciales: 4 SHA-256 separados por dominio y carril.
    pub fn new(seed: &[u8; 32], domain: u8) -> Self {
        let mut raw = [0u8; 128];
        for i in 0..4usize {
            let h = sha256_cat(&[b"ARMAX-AESGEN-v0", seed, &[domain, i as u8]]);
            raw[32 * i..32 * (i + 1)].copy_from_slice(&h);
        }
        let mut st = [[0u8; 16]; 4];
        let mut key = [[0u8; 16]; 4];
        for l in 0..4 {
            st[l].copy_from_slice(&raw[16 * l..16 * l + 16]);
            key[l].copy_from_slice(&raw[64 + 16 * l..64 + 16 * l + 16]);
        }
        Self { st, key, _b: PhantomData }
    }

    /// Rellena `out` (múltiplo de 64 bytes). Carriles pares: ronda inversa; impares: directa.
    pub fn fill(&mut self, out: &mut [u8]) {
        assert!(out.len() % 64 == 0, "el buffer debe ser múltiplo de 64 bytes");
        for chunk in out.chunks_exact_mut(64) {
            for l in 0..4 {
                self.st[l] = if l % 2 == 0 {
                    B::dec_round(self.st[l], self.key[l])
                } else {
                    B::enc_round(self.st[l], self.key[l])
                };
                chunk[16 * l..16 * l + 16].copy_from_slice(&self.st[l]);
            }
        }
    }
}

/// Programa de `len` instrucciones derivado de la semilla (`len` múltiplo de 8).
pub fn gen_program<B: Aes>(seed: &[u8; 32], len: usize) -> Vec<Instr> {
    assert!(len % 8 == 0, "len debe ser múltiplo de 8 (buffer múltiplo de 64 B)");
    let mut buf = vec![0u8; len * INSTR_BYTES];
    AesGen::<B>::new(seed, DOM_PROGRAM).fill(&mut buf);
    buf.chunks_exact(INSTR_BYTES)
        .map(|c| Instr::decode(c.try_into().unwrap()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes::Portable;

    #[test]
    fn deterministic_and_seed_sensitive() {
        let mut a = vec![0u8; 4096];
        let mut b = vec![0u8; 4096];
        let mut c = vec![0u8; 4096];
        AesGen::<Portable>::new(&[7u8; 32], 2).fill(&mut a);
        AesGen::<Portable>::new(&[7u8; 32], 2).fill(&mut b);
        AesGen::<Portable>::new(&[8u8; 32], 2).fill(&mut c);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(&a[..64], &a[64..128]);
    }

    #[test]
    fn chunked_fill_equals_single_fill() {
        let mut whole = vec![0u8; 1024];
        AesGen::<Portable>::new(&[1u8; 32], 2).fill(&mut whole);
        let mut parts = vec![0u8; 1024];
        let mut g = AesGen::<Portable>::new(&[1u8; 32], 2);
        for ch in parts.chunks_mut(256) {
            g.fill(ch);
        }
        assert_eq!(whole, parts);
    }

    #[test]
    fn domains_are_separated() {
        let s = [3u8; 32];
        let mut a = vec![0u8; 64];
        let mut b = vec![0u8; 64];
        AesGen::<Portable>::new(&s, DOM_PROGRAM).fill(&mut a);
        AesGen::<Portable>::new(&s, DOM_SCRATCH).fill(&mut b);
        assert_ne!(a, b);
    }
}
