//! Raíz de Merkle con separación de dominio entre hojas y nodos.
//!
//! Un nodo sin pareja se **promueve** sin cambios (no se duplica), así que
//! `[a, b, c]` y `[a, b, c, c]` dan raíces distintas: no existe la mutabilidad de
//! CVE-2012-2459 de Bitcoin.

use armax_pow::Hash32;
use armax_vm::sha256::{sha256, sha256_cat};

fn leaf(x: &Hash32) -> Hash32 {
    sha256_cat(&[&[0x00], x])
}

fn node(a: &Hash32, b: &Hash32) -> Hash32 {
    sha256_cat(&[&[0x01], a, b])
}

pub fn merkle_root(leaves: &[Hash32]) -> Hash32 {
    if leaves.is_empty() {
        return sha256(b"ARMAX-MERKLE-EMPTY-v0");
    }
    let mut level: Vec<Hash32> = leaves.iter().map(leaf).collect();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|c| if c.len() == 2 { node(&c[0], &c[1]) } else { c[0] })
            .collect();
    }
    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_leaf_is_domain_separated() {
        let a = [1u8; 32];
        assert_ne!(merkle_root(&[a]), a);
        assert_eq!(merkle_root(&[a]), leaf(&a));
    }

    #[test]
    fn order_matters() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        assert_ne!(merkle_root(&[a, b]), merkle_root(&[b, a]));
    }

    #[test]
    fn odd_leaf_is_not_duplicated() {
        let (a, b, c) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        assert_ne!(merkle_root(&[a, b, c]), merkle_root(&[a, b, c, c]));
    }

    #[test]
    fn leaf_cannot_be_confused_with_node() {
        // Una hoja con el valor de un nodo interno no puede producir la misma raíz.
        let (a, b) = ([1u8; 32], [2u8; 32]);
        let inner = node(&leaf(&a), &leaf(&b));
        assert_ne!(merkle_root(&[a, b]), merkle_root(&[inner]));
    }

    #[test]
    fn empty_is_defined() {
        assert_eq!(merkle_root(&[]), sha256(b"ARMAX-MERKLE-EMPTY-v0"));
    }
}
