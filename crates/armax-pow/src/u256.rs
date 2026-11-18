//! Entero sin signo de 256 bits (consenso: solo aritmética entera, sin flotantes).
//!
//! Representación: 4 limbs de 64 bits en orden little-endian (`limbs[0]` es el menos
//! significativo). La serialización a bytes es big-endian, de modo que un digest de
//! 32 bytes se interpreta directamente como número y se compara con el target.

use core::cmp::Ordering;
use core::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct U256(pub [u64; 4]);

impl U256 {
    pub const ZERO: U256 = U256([0; 4]);
    pub const ONE: U256 = U256([1, 0, 0, 0]);
    pub const MAX: U256 = U256([u64::MAX; 4]);

    pub const fn from_u64(x: u64) -> Self {
        U256([x, 0, 0, 0])
    }

    pub const fn from_u128(x: u128) -> Self {
        U256([x as u64, (x >> 64) as u64, 0, 0])
    }

    pub fn from_be_bytes(b: &[u8; 32]) -> Self {
        let mut l = [0u64; 4];
        for i in 0..4 {
            let off = (3 - i) * 8;
            l[i] = u64::from_be_bytes(b[off..off + 8].try_into().unwrap());
        }
        U256(l)
    }

    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut b = [0u8; 32];
        for i in 0..4 {
            let off = (3 - i) * 8;
            b[off..off + 8].copy_from_slice(&self.0[i].to_be_bytes());
        }
        b
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0; 4]
    }

    /// Longitud en bits (0 para el cero).
    pub fn bits(&self) -> u32 {
        for i in (0..4).rev() {
            if self.0[i] != 0 {
                return 64 * i as u32 + (64 - self.0[i].leading_zeros());
            }
        }
        0
    }

    /// `2^n` para `n < 256`.
    pub fn pow2(n: u32) -> Option<Self> {
        if n >= 256 {
            return None;
        }
        let mut l = [0u64; 4];
        l[(n / 64) as usize] = 1u64 << (n % 64);
        Some(U256(l))
    }

    fn bit(&self, i: u32) -> bool {
        (self.0[(i / 64) as usize] >> (i % 64)) & 1 == 1
    }

    /// Desplazamiento a la izquierda (descarta los bits que salen). `n < 256`.
    pub fn shl(&self, n: u32) -> Self {
        assert!(n < 256);
        let (ws, bs) = ((n / 64) as usize, n % 64);
        let mut out = [0u64; 4];
        for i in ws..4 {
            let src = i - ws;
            let mut v = self.0[src] << bs;
            if bs > 0 && src > 0 {
                v |= self.0[src - 1] >> (64 - bs);
            }
            out[i] = v;
        }
        U256(out)
    }

    /// Desplazamiento a la derecha. `n < 256`.
    pub fn shr(&self, n: u32) -> Self {
        assert!(n < 256);
        let (ws, bs) = ((n / 64) as usize, n % 64);
        let mut out = [0u64; 4];
        for i in 0..4 {
            let src = i + ws;
            if src < 4 {
                let mut v = self.0[src] >> bs;
                if bs > 0 && src + 1 < 4 {
                    v |= self.0[src + 1] << (64 - bs);
                }
                out[i] = v;
            }
        }
        U256(out)
    }

    pub fn overflowing_add(self, o: Self) -> (Self, bool) {
        let mut out = [0u64; 4];
        let mut carry = false;
        for i in 0..4 {
            let (a, c1) = self.0[i].overflowing_add(o.0[i]);
            let (b, c2) = a.overflowing_add(carry as u64);
            out[i] = b;
            carry = c1 || c2;
        }
        (U256(out), carry)
    }

    pub fn overflowing_sub(self, o: Self) -> (Self, bool) {
        let mut out = [0u64; 4];
        let mut borrow = false;
        for i in 0..4 {
            let (a, b1) = self.0[i].overflowing_sub(o.0[i]);
            let (b, b2) = a.overflowing_sub(borrow as u64);
            out[i] = b;
            borrow = b1 || b2;
        }
        (U256(out), borrow)
    }

    pub fn checked_add(self, o: Self) -> Option<Self> {
        let (r, c) = self.overflowing_add(o);
        if c {
            None
        } else {
            Some(r)
        }
    }

    pub fn checked_sub(self, o: Self) -> Option<Self> {
        let (r, b) = self.overflowing_sub(o);
        if b {
            None
        } else {
            Some(r)
        }
    }

    /// `floor(self * m / d)` con producto intermedio de 320 bits.
    /// `None` si `d == 0` o si el resultado no cabe en 256 bits.
    pub fn mul_div_u64(self, m: u64, d: u64) -> Option<Self> {
        if d == 0 {
            return None;
        }
        let mut p = [0u64; 5];
        let mut carry: u128 = 0;
        for i in 0..4 {
            let cur = self.0[i] as u128 * m as u128 + carry;
            p[i] = cur as u64;
            carry = cur >> 64;
        }
        p[4] = carry as u64;

        let mut q = [0u64; 5];
        let mut rem: u64 = 0;
        for i in (0..5).rev() {
            let cur = ((rem as u128) << 64) | p[i] as u128;
            q[i] = (cur / d as u128) as u64;
            rem = (cur % d as u128) as u64;
        }
        if q[4] != 0 {
            return None;
        }
        Some(U256([q[0], q[1], q[2], q[3]]))
    }

    /// `floor(self / d)`. Panics si `d == 0`.
    pub fn div_u64(self, d: u64) -> Self {
        assert!(d != 0, "división por cero");
        self.mul_div_u64(1, d).unwrap()
    }

    /// Cociente y resto. Panics si `rhs` es cero. División binaria: 256 iteraciones, sin ramas
    /// dependientes de tamaño; se usa solo para el trabajo acumulado, no en el camino caliente.
    pub fn div_rem(self, rhs: Self) -> (Self, Self) {
        assert!(!rhs.is_zero(), "división por cero");
        let mut q = U256::ZERO;
        let mut r = U256::ZERO;
        for i in (0..256u32).rev() {
            let carry = r.bit(255);
            r = r.shl(1);
            if self.bit(i) {
                r.0[0] |= 1;
            }
            if carry || r >= rhs {
                r = r.overflowing_sub(rhs).0; // con `carry` la resta envuelve al valor correcto
                q.0[(i / 64) as usize] |= 1u64 << (i % 64);
            }
        }
        (q, r)
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => continue,
                o => return o,
            }
        }
        Ordering::Equal
    }
}

impl fmt::Debug for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;
        for b in self.to_be_bytes() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Display for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Trabajo esperado de un bloque con ese target: `floor(2^256 / (target + 1))`.
/// Se usa para elegir la cadena de mayor trabajo acumulado.
pub fn block_work(target: &U256) -> U256 {
    if *target == U256::MAX {
        return U256::ONE;
    }
    // 2^256 / (t+1) = (~t / (t+1)) + 1  (identidad de Bitcoin Core)
    let not_t = U256([!target.0[0], !target.0[1], !target.0[2], !target.0[3]]);
    let (q, _) = not_t.div_rem(target.checked_add(U256::ONE).unwrap());
    q.checked_add(U256::ONE).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn u256(&mut self) -> U256 {
            U256([self.next(), self.next(), self.next(), self.next()])
        }
    }

    #[test]
    fn bytes_roundtrip_and_endianness() {
        let mut r = Rng(1);
        for _ in 0..100 {
            let x = r.u256();
            assert_eq!(U256::from_be_bytes(&x.to_be_bytes()), x);
        }
        let mut b = [0u8; 32];
        b[31] = 1;
        assert_eq!(U256::from_be_bytes(&b), U256::ONE);
        b = [0u8; 32];
        b[0] = 0x80;
        assert_eq!(U256::from_be_bytes(&b), U256::pow2(255).unwrap());
    }

    #[test]
    fn ordering_is_numeric() {
        assert!(U256::from_u64(5) < U256::from_u64(6));
        assert!(U256::pow2(200).unwrap() > U256::from_u128(u128::MAX));
        assert!(U256::MAX > U256::pow2(255).unwrap());
        assert_eq!(U256::ZERO, U256::default());
    }

    #[test]
    fn shifts() {
        for n in [0u32, 1, 63, 64, 65, 127, 128, 200, 255] {
            assert_eq!(U256::ONE.shl(n), U256::pow2(n).unwrap());
            assert_eq!(U256::pow2(n).unwrap().shr(n), U256::ONE);
        }
        assert_eq!(U256::MAX.shr(255), U256::ONE);
        assert_eq!(U256::pow2(255).unwrap().shl(1), U256::ZERO); // desborda y se descarta
    }

    #[test]
    fn add_sub_carry() {
        let a = U256::from_u128(u128::MAX);
        assert_eq!(a.checked_add(U256::ONE).unwrap(), U256::pow2(128).unwrap());
        assert_eq!(U256::pow2(128).unwrap().checked_sub(U256::ONE).unwrap(), a);
        assert!(U256::MAX.checked_add(U256::ONE).is_none());
        assert!(U256::ZERO.checked_sub(U256::ONE).is_none());
        assert_eq!(U256::ZERO.overflowing_sub(U256::ONE).0, U256::MAX);
    }

    #[test]
    fn mul_div_matches_u128() {
        let mut r = Rng(7);
        for _ in 0..2000 {
            let x = (r.next() >> 8) as u128 * (r.next() >> 8) as u128; // < 2^112
            let m = r.next() >> 16;
            let d = (r.next() >> 8).max(1);
            let want = x * m as u128 / d as u128; // cabe: x*m < 2^160? no -> usar comprobación U256
            let got = U256::from_u128(x).mul_div_u64(m, d);
            // x*m puede exceder u128; solo comparamos cuando no desborda
            if let Some(p) = x.checked_mul(m as u128) {
                assert_eq!(got, Some(U256::from_u128(p / d as u128)));
                let _ = want;
            }
        }
    }

    #[test]
    fn mul_div_edges() {
        assert_eq!(U256::MAX.mul_div_u64(1, 1), Some(U256::MAX));
        assert_eq!(U256::MAX.mul_div_u64(2, 1), None); // desborda
        assert_eq!(U256::MAX.mul_div_u64(2, 2), Some(U256::MAX)); // 320 bits intermedios
        assert_eq!(U256::from_u64(10).mul_div_u64(3, 0), None);
        assert_eq!(U256::MAX.div_u64(2), U256::pow2(255).unwrap().checked_sub(U256::ONE).unwrap());
        assert_eq!(U256::pow2(255).unwrap().mul_div_u64(3, 3), Some(U256::pow2(255).unwrap()));
    }

    #[test]
    fn div_rem_identity_small_and_large() {
        let mut r = Rng(99);
        for _ in 0..500 {
            let a = U256::from_u128(((r.next() as u128) << 64) | r.next() as u128);
            let b = U256::from_u128((r.next() >> 1) as u128 + 1);
            let (q, rem) = a.div_rem(b);
            let (av, bv) = (((a.0[1] as u128) << 64) | a.0[0] as u128, ((b.0[1] as u128) << 64) | b.0[0] as u128);
            assert_eq!(q, U256::from_u128(av / bv));
            assert_eq!(rem, U256::from_u128(av % bv));
        }
        // 2^200 / 2^100 = 2^100 ; MAX / MAX = 1 ; MAX / 1 = MAX
        assert_eq!(U256::pow2(200).unwrap().div_rem(U256::pow2(100).unwrap()), (U256::pow2(100).unwrap(), U256::ZERO));
        assert_eq!(U256::MAX.div_rem(U256::MAX), (U256::ONE, U256::ZERO));
        assert_eq!(U256::MAX.div_rem(U256::ONE), (U256::MAX, U256::ZERO));
        // Divisor con el bit 255 activo (caso del acarreo en el desplazamiento).
        let big = U256::pow2(255).unwrap();
        let (q, rem) = U256::MAX.div_rem(big);
        assert_eq!(q, U256::ONE);
        assert_eq!(rem, U256::MAX.checked_sub(big).unwrap());
    }

    #[test]
    fn div_rem_reconstructs_random_256bit() {
        // a == q*b + r con q*b calculado por sumas de desplazamientos (sin depender de div_rem).
        let mut r = Rng(5);
        for _ in 0..200 {
            let a = r.u256();
            let b = r.u256().shr((r.next() % 200) as u32);
            if b.is_zero() {
                continue;
            }
            let (q, rem) = a.div_rem(b);
            assert!(rem < b);
            let mut acc = U256::ZERO;
            for i in 0..256u32 {
                if q.bit(i) {
                    acc = acc.checked_add(b.shl(i.min(255))).unwrap_or(U256::MAX);
                    // b.shl(i) pierde bits si desborda; q*b <= a asegura que no ocurre
                }
            }
            assert_eq!(acc.checked_add(rem), Some(a));
        }
    }

    #[test]
    fn work_values() {
        // target = 2^255 - 1 -> trabajo 2 ; target = 2^254 - 1 -> 4 ; target MAX -> 1
        let t255 = U256::pow2(255).unwrap().checked_sub(U256::ONE).unwrap();
        assert_eq!(block_work(&t255), U256::from_u64(2));
        let t254 = U256::pow2(254).unwrap().checked_sub(U256::ONE).unwrap();
        assert_eq!(block_work(&t254), U256::from_u64(4));
        assert_eq!(block_work(&U256::MAX), U256::ONE);
        // más difícil (target menor) => más trabajo
        assert!(block_work(&U256::from_u64(1000)) > block_work(&U256::from_u64(2000)));
    }

    #[test]
    fn bits_len() {
        assert_eq!(U256::ZERO.bits(), 0);
        assert_eq!(U256::ONE.bits(), 1);
        assert_eq!(U256::pow2(255).unwrap().bits(), 256);
        assert_eq!(U256::from_u64(255).bits(), 8);
    }
}
