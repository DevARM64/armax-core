//! X25519 (RFC 7748): escalera de Montgomery sobre el mismo campo que `ed25519`.
//! Sin ramas ni accesos a memoria dependientes del escalar (intercambio condicional por máscara).

use crate::ed25519::Fe;

pub const KEY_LEN: usize = 32;

/// Punto base (u = 9).
pub const BASEPOINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

/// `scalar · u`. El escalar se "recorta" (clamp) como pide el RFC. Si `u` es un punto de orden
/// bajo el resultado es todo ceros: quien negocie claves debe rechazarlo (`is_all_zero`).
pub fn x25519(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;

    let x1 = Fe::from_bytes(u); // ignora el bit 255, como pide el RFC
    let (mut x2, mut z2) = (Fe::ONE, Fe::ZERO);
    let (mut x3, mut z3) = (x1, Fe::ONE);
    let a24 = Fe::small(121665);
    let mut swap = 0u64;
    for t in (0..255).rev() {
        let bit = ((k[t / 8] >> (t % 8)) & 1) as u64;
        swap ^= bit;
        let (nx2, nx3) = (Fe::select(&x2, &x3, swap), Fe::select(&x3, &x2, swap));
        let (nz2, nz3) = (Fe::select(&z2, &z3, swap), Fe::select(&z3, &z2, swap));
        x2 = nx2;
        x3 = nx3;
        z2 = nz2;
        z3 = nz3;
        swap = bit;

        let a = x2.add(&z2);
        let aa = a.square();
        let b = x2.sub(&z2);
        let bb = b.square();
        let e = aa.sub(&bb);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);
        x3 = da.add(&cb).square();
        z3 = x1.mul(&da.sub(&cb).square());
        x2 = aa.mul(&bb);
        z2 = e.mul(&aa.add(&a24.mul(&e)));
    }
    let (nx2, nz2) = (Fe::select(&x2, &x3, swap), Fe::select(&z2, &z3, swap));
    nx2.mul(&nz2.invert()).to_bytes()
}

/// Clave pública de un secreto de 32 bytes.
pub fn public_key(secret: &[u8; 32]) -> [u8; 32] {
    x25519(secret, &BASEPOINT)
}

/// ¿Todo ceros? (resultado de un punto de orden bajo: hay que abortar el acuerdo).
pub fn is_all_zero(x: &[u8; 32]) -> bool {
    x.iter().fold(0u8, |a, b| a | b) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> [u8; 32] {
        let v: Vec<u8> = (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect();
        v.try_into().unwrap()
    }

    #[test]
    fn rfc7748_vectors() {
        let k = h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        assert_eq!(x25519(&k, &u), h("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"));
        let k = h("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let u = h("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        assert_eq!(x25519(&k, &u), h("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"));
    }

    #[test]
    fn rfc7748_diffie_hellman() {
        let a = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let b = h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let (pa, pb) = (public_key(&a), public_key(&b));
        assert_eq!(pa, h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
        assert_eq!(pb, h("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));
        let s = h("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(x25519(&a, &pb), s);
        assert_eq!(x25519(&b, &pa), s);
    }

    #[test]
    fn rfc7748_iterated_once_and_thousand() {
        let (mut k, mut u) = (BASEPOINT, BASEPOINT);
        for i in 1..=1000 {
            let r = x25519(&k, &u);
            u = k;
            k = r;
            if i == 1 {
                assert_eq!(k, h("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"));
            }
        }
        assert_eq!(k, h("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"));
    }

    #[test]
    fn low_order_points_give_zero() {
        let k = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        assert!(is_all_zero(&x25519(&k, &[0u8; 32])));
        let mut one = [0u8; 32];
        one[0] = 1;
        assert!(is_all_zero(&x25519(&k, &one)));
    }
}
