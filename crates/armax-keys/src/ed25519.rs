//! Ed25519 (RFC 8032) sin dependencias.
//!
//! * Campo 2^255-19 con 5 limbs de 51 bits (aritmética `u64`/`u128`, sin ramas por dato).
//! * Curva de Edwards torcida en coordenadas extendidas.
//! * Multiplicación escalar de ventana fija con selección sin ramas (`cmov`): el tiempo no
//!   depende de los bits del escalar. Las inversiones/raíces usan exponentes públicos fijos.
//!   Es una implementación sencilla y verificable, no la más rápida; la firma tarda decenas de
//!   microsegundos a unos pocos ms en un teléfono.
//!
//! **Verificación estricta (consenso):** se rechaza `S >= L` (sin maleabilidad de `S`), una clave
//! pública con `y >= p` o que no esté en la curva, y una clave de orden pequeño (`[8]A = 0`).
//! La ecuación se comprueba recalculando `R' = [S]B - [k]A` y comparando su codificación con `R`,
//! así `R` también debe ser canónico. Con esto cada par (clave, mensaje, firma) tiene una única
//! lectura válida: todos los nodos aceptan o rechazan igual.

use std::sync::OnceLock;

use crate::sha512::{sha512, Sha512};

// ------------------------------------------------------------------------------------------
// Borrado de secretos
// ------------------------------------------------------------------------------------------

/// Pone a cero la memoria sin que el optimizador pueda eliminar la escritura.
pub fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` es una referencia válida y alineada a un `u8`.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

// ------------------------------------------------------------------------------------------
// Campo F_p, p = 2^255 - 19
// ------------------------------------------------------------------------------------------

const MASK: u64 = (1 << 51) - 1;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Fe([u64; 5]);

fn m(a: u64, b: u64) -> u128 {
    a as u128 * b as u128
}

impl Fe {
    pub(crate) const ZERO: Fe = Fe([0; 5]);
    pub(crate) const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    pub(crate) fn small(x: u64) -> Fe {
        Fe([x, 0, 0, 0, 0])
    }

    pub(crate) fn reduce(mut l: [u64; 5]) -> Fe {
        let c0 = l[0] >> 51;
        let c1 = l[1] >> 51;
        let c2 = l[2] >> 51;
        let c3 = l[3] >> 51;
        let c4 = l[4] >> 51;
        for x in l.iter_mut() {
            *x &= MASK;
        }
        l[0] += c4 * 19;
        l[1] += c0;
        l[2] += c1;
        l[3] += c2;
        l[4] += c3;
        Fe(l)
    }

    pub(crate) fn add(&self, o: &Fe) -> Fe {
        let (a, b) = (&self.0, &o.0);
        Fe::reduce([a[0] + b[0], a[1] + b[1], a[2] + b[2], a[3] + b[3], a[4] + b[4]])
    }

    pub(crate) fn sub(&self, o: &Fe) -> Fe {
        // suma 16p para no pasar por debajo de cero
        let (a, b) = (&self.0, &o.0);
        Fe::reduce([
            (a[0] + 36028797018963664) - b[0],
            (a[1] + 36028797018963952) - b[1],
            (a[2] + 36028797018963952) - b[2],
            (a[3] + 36028797018963952) - b[3],
            (a[4] + 36028797018963952) - b[4],
        ])
    }

    pub(crate) fn neg(&self) -> Fe {
        Fe::ZERO.sub(self)
    }

    pub(crate) fn mul(&self, o: &Fe) -> Fe {
        let (a, b) = (&self.0, &o.0);
        let (b1_19, b2_19, b3_19, b4_19) = (b[1] * 19, b[2] * 19, b[3] * 19, b[4] * 19);
        let c0 = m(a[0], b[0]) + m(a[4], b1_19) + m(a[3], b2_19) + m(a[2], b3_19) + m(a[1], b4_19);
        let mut c1 = m(a[1], b[0]) + m(a[0], b[1]) + m(a[4], b2_19) + m(a[3], b3_19) + m(a[2], b4_19);
        let mut c2 = m(a[2], b[0]) + m(a[1], b[1]) + m(a[0], b[2]) + m(a[4], b3_19) + m(a[3], b4_19);
        let mut c3 = m(a[3], b[0]) + m(a[2], b[1]) + m(a[1], b[2]) + m(a[0], b[3]) + m(a[4], b4_19);
        let mut c4 = m(a[4], b[0]) + m(a[3], b[1]) + m(a[2], b[2]) + m(a[1], b[3]) + m(a[0], b[4]);

        let mut out = [0u64; 5];
        out[0] = (c0 as u64) & MASK;
        c1 += (c0 >> 51) as u64 as u128;
        out[1] = (c1 as u64) & MASK;
        c2 += (c1 >> 51) as u64 as u128;
        out[2] = (c2 as u64) & MASK;
        c3 += (c2 >> 51) as u64 as u128;
        out[3] = (c3 as u64) & MASK;
        c4 += (c3 >> 51) as u64 as u128;
        out[4] = (c4 as u64) & MASK;
        let carry = (c4 >> 51) as u64;
        out[0] += carry * 19;
        out[1] += out[0] >> 51;
        out[0] &= MASK;
        Fe(out)
    }

    pub(crate) fn square(&self) -> Fe {
        self.mul(self)
    }

    /// `choice` ∈ {0,1}: devuelve `b` si 1, `a` si 0, sin ramas.
    pub(crate) fn select(a: &Fe, b: &Fe, choice: u64) -> Fe {
        let mask = 0u64.wrapping_sub(choice);
        let mut o = [0u64; 5];
        for i in 0..5 {
            o[i] = a.0[i] ^ ((a.0[i] ^ b.0[i]) & mask);
        }
        Fe(o)
    }

    pub(crate) fn from_bytes(b: &[u8; 32]) -> Fe {
        let w = |i: usize| u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().unwrap());
        let (w0, w1, w2, w3) = (w(0), w(1), w(2), w(3));
        Fe([
            w0 & MASK,
            ((w0 >> 51) | (w1 << 13)) & MASK,
            ((w1 >> 38) | (w2 << 26)) & MASK,
            ((w2 >> 25) | (w3 << 39)) & MASK,
            (w3 >> 12) & MASK, // ignora el bit 255
        ])
    }

    /// Codificación canónica (completamente reducida) de 32 bytes little-endian.
    pub(crate) fn to_bytes(&self) -> [u8; 32] {
        let mut l = Fe::reduce(self.0).0;
        // q = 1 si el valor >= p
        let mut q = (l[0] + 19) >> 51;
        q = (l[1] + q) >> 51;
        q = (l[2] + q) >> 51;
        q = (l[3] + q) >> 51;
        q = (l[4] + q) >> 51;
        l[0] += 19 * q;
        l[1] += l[0] >> 51;
        l[0] &= MASK;
        l[2] += l[1] >> 51;
        l[1] &= MASK;
        l[3] += l[2] >> 51;
        l[2] &= MASK;
        l[4] += l[3] >> 51;
        l[3] &= MASK;
        l[4] &= MASK;
        let w0 = l[0] | (l[1] << 51);
        let w1 = (l[1] >> 13) | (l[2] << 38);
        let w2 = (l[2] >> 26) | (l[3] << 25);
        let w3 = (l[3] >> 39) | (l[4] << 12);
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&w0.to_le_bytes());
        out[8..16].copy_from_slice(&w1.to_le_bytes());
        out[16..24].copy_from_slice(&w2.to_le_bytes());
        out[24..32].copy_from_slice(&w3.to_le_bytes());
        out
    }

    pub(crate) fn is_negative(&self) -> u64 {
        (self.to_bytes()[0] & 1) as u64
    }

    pub(crate) fn eq(&self, o: &Fe) -> bool {
        self.to_bytes() == o.to_bytes()
    }

    /// `self^exp` con exponente público (ramas por bits del exponente, no del valor).
    pub(crate) fn pow(&self, exp: &[u64; 4]) -> Fe {
        let mut r = Fe::ONE;
        for i in (0..256).rev() {
            r = r.square();
            if (exp[i / 64] >> (i % 64)) & 1 == 1 {
                r = r.mul(self);
            }
        }
        r
    }

    /// 1/self = self^(p-2)
    pub(crate) fn invert(&self) -> Fe {
        self.pow(&[0xffff_ffff_ffff_ffeb, u64::MAX, u64::MAX, 0x7fff_ffff_ffff_ffff])
    }

    /// self^((p-5)/8) = self^(2^252 - 3)
    pub(crate) fn pow_p58(&self) -> Fe {
        self.pow(&[0xffff_ffff_ffff_fffd, u64::MAX, u64::MAX, 0x0fff_ffff_ffff_ffff])
    }
}

struct Consts {
    d: Fe,
    d2: Fe,
    sqrt_m1: Fe,
    basepoint: Point,
}

fn consts() -> &'static Consts {
    static C: OnceLock<Consts> = OnceLock::new();
    C.get_or_init(|| {
        // d = -121665/121666
        let d = Fe::small(121665).neg().mul(&Fe::small(121666).invert());
        let d2 = d.add(&d);
        // sqrt(-1) = 2^((p-1)/4) = 2^(2^253 - 5)
        let sqrt_m1 = Fe::small(2).pow(&[0xffff_ffff_ffff_fffb, u64::MAX, u64::MAX, 0x1fff_ffff_ffff_ffff]);
        // B: y = 4/5, x par
        let mut by = [0x66u8; 32];
        by[0] = 0x58;
        let basepoint = decompress_with(&by, &d, &sqrt_m1).expect("el punto base es válido");
        Consts { d, d2, sqrt_m1, basepoint }
    })
}

// ------------------------------------------------------------------------------------------
// Curva
// ------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

impl Point {
    const IDENTITY: Point = Point { x: Fe::ZERO, y: Fe::ONE, z: Fe::ONE, t: Fe::ZERO };

    fn add(&self, o: &Point) -> Point {
        let c = consts();
        let a = self.y.sub(&self.x).mul(&o.y.sub(&o.x));
        let b = self.y.add(&self.x).mul(&o.y.add(&o.x));
        let cc = self.t.mul(&c.d2).mul(&o.t);
        let dd = self.z.add(&self.z).mul(&o.z);
        let e = b.sub(&a);
        let f = dd.sub(&cc);
        let g = dd.add(&cc);
        let h = b.add(&a);
        Point { x: e.mul(&f), y: g.mul(&h), z: f.mul(&g), t: e.mul(&h) }
    }

    fn double(&self) -> Point {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square();
        let c = c.add(&c);
        let d = a.neg();
        let e = self.x.add(&self.y).square().sub(&a).sub(&b);
        let g = d.add(&b);
        let f = g.sub(&c);
        let h = d.sub(&b);
        Point { x: e.mul(&f), y: g.mul(&h), z: f.mul(&g), t: e.mul(&h) }
    }

    fn neg(&self) -> Point {
        Point { x: self.x.neg(), y: self.y, z: self.z, t: self.t.neg() }
    }

    fn select(a: &Point, b: &Point, choice: u64) -> Point {
        Point {
            x: Fe::select(&a.x, &b.x, choice),
            y: Fe::select(&a.y, &b.y, choice),
            z: Fe::select(&a.z, &b.z, choice),
            t: Fe::select(&a.t, &b.t, choice),
        }
    }

    /// `[scalar]P`, escalar de 256 bits little-endian. Tiempo independiente del escalar.
    fn mul_scalar(&self, scalar: &[u8; 32]) -> Point {
        let mut acc = Point::IDENTITY;
        for i in (0..256).rev() {
            acc = acc.double();
            let bit = ((scalar[i / 8] >> (i % 8)) & 1) as u64;
            let sum = acc.add(self);
            acc = Point::select(&acc, &sum, bit);
        }
        acc
    }

    fn compress(&self) -> [u8; 32] {
        let zi = self.z.invert();
        let x = self.x.mul(&zi);
        let y = self.y.mul(&zi);
        let mut out = y.to_bytes();
        out[31] |= (x.is_negative() as u8) << 7;
        out
    }

    fn is_identity(&self) -> bool {
        self.x.eq(&Fe::ZERO) && self.y.eq(&self.z)
    }

    fn mul_by_cofactor(&self) -> Point {
        self.double().double().double()
    }
}

fn decompress_with(b: &[u8; 32], d: &Fe, sqrt_m1: &Fe) -> Option<Point> {
    let sign = (b[31] >> 7) as u64;
    let mut yb = *b;
    yb[31] &= 0x7f;
    let y = Fe::from_bytes(&yb);
    if y.to_bytes() != yb {
        return None; // y >= p: codificación no canónica
    }
    let y2 = y.square();
    let u = y2.sub(&Fe::ONE);
    let v = d.mul(&y2).add(&Fe::ONE);
    // x = u v^3 (u v^7)^((p-5)/8)
    let v3 = v.square().mul(&v);
    let v7 = v3.square().mul(&v);
    let mut x = u.mul(&v3).mul(&u.mul(&v7).pow_p58());
    let vx2 = v.mul(&x.square());
    if vx2.eq(&u) {
        // ok
    } else if vx2.eq(&u.neg()) {
        x = x.mul(sqrt_m1);
    } else {
        return None; // no es un cuadrado: no está en la curva
    }
    if x.eq(&Fe::ZERO) && sign == 1 {
        return None;
    }
    if x.is_negative() != sign {
        x = x.neg();
    }
    Some(Point { x, y, z: Fe::ONE, t: x.mul(&y) })
}

fn decompress(b: &[u8; 32]) -> Option<Point> {
    let c = consts();
    decompress_with(b, &c.d, &c.sqrt_m1)
}

// ------------------------------------------------------------------------------------------
// Escalares mod L, L = 2^252 + 27742317777372353535851937790883648493
// ------------------------------------------------------------------------------------------

const L: [u64; 4] = [0x5812_631a_5cf5_d3ed, 0x14de_f9de_a2f7_9cd6, 0, 0x1000_0000_0000_0000];

fn sub_limbs(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], u64) {
    let mut out = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        out[i] = d2;
        borrow = (b1 | b2) as u64;
    }
    (out, borrow)
}

/// ¿`s` (32 bytes LE) es canónico, es decir `s < L`?
fn scalar_is_canonical(s: &[u8; 32]) -> bool {
    let limbs = to_limbs(s);
    sub_limbs(&limbs, &L).1 == 1
}

fn to_limbs(s: &[u8; 32]) -> [u64; 4] {
    let mut l = [0u64; 4];
    for i in 0..4 {
        l[i] = u64::from_le_bytes(s[8 * i..8 * i + 8].try_into().unwrap());
    }
    l
}

fn from_limbs(l: &[u64; 4]) -> [u8; 32] {
    let mut o = [0u8; 32];
    for i in 0..4 {
        o[8 * i..8 * i + 8].copy_from_slice(&l[i].to_le_bytes());
    }
    o
}

/// Reduce un entero de 512 bits (8 limbs LE) módulo L, sin ramas por dato.
fn reduce_wide(x: &[u64; 8]) -> [u64; 4] {
    let mut r = [0u64; 4];
    for bit in (0..512).rev() {
        // r = 2r + bit  (r < L < 2^253 => no desborda)
        let b = (x[bit / 64] >> (bit % 64)) & 1;
        r = [
            (r[0] << 1) | b,
            (r[1] << 1) | (r[0] >> 63),
            (r[2] << 1) | (r[1] >> 63),
            (r[3] << 1) | (r[2] >> 63),
        ];
        let (d, borrow) = sub_limbs(&r, &L);
        let mask = 0u64.wrapping_sub(borrow); // borrow=1 => r < L => conservar r
        for i in 0..4 {
            r[i] = (r[i] & mask) | (d[i] & !mask);
        }
    }
    r
}

fn reduce_bytes64(h: &[u8; 64]) -> [u8; 32] {
    let mut w = [0u64; 8];
    for i in 0..8 {
        w[i] = u64::from_le_bytes(h[8 * i..8 * i + 8].try_into().unwrap());
    }
    from_limbs(&reduce_wide(&w))
}

/// `(a·b + c) mod L`
fn scalar_mul_add(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let (a, b, c) = (to_limbs(a), to_limbs(b), to_limbs(c));
    let mut wide = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let t = wide[i + j] as u128 + a[i] as u128 * b[j] as u128 + carry;
            wide[i + j] = t as u64;
            carry = t >> 64;
        }
        wide[i + 4] = carry as u64;
    }
    let mut carry = 0u128;
    for i in 0..8 {
        let add = if i < 4 { c[i] as u128 } else { 0 };
        let t = wide[i] as u128 + add + carry;
        wide[i] = t as u64;
        carry = t >> 64;
    }
    debug_assert_eq!(carry, 0);
    from_limbs(&reduce_wide(&wide))
}

// ------------------------------------------------------------------------------------------
// API pública
// ------------------------------------------------------------------------------------------

pub const SEED_LEN: usize = 32;
pub const PUBLIC_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

/// Expande la semilla (RFC 8032 §5.1.5): escalar con "clamping" y prefijo.
fn expand(seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut h = sha512(seed);
    let mut a = [0u8; 32];
    let mut prefix = [0u8; 32];
    a.copy_from_slice(&h[..32]);
    prefix.copy_from_slice(&h[32..]);
    wipe(&mut h);
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    (a, prefix)
}

/// Clave pública de una semilla de 32 bytes.
pub fn public_key_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    let (mut a, mut prefix) = expand(seed);
    let pk = consts().basepoint.mul_scalar(&a).compress();
    wipe(&mut a);
    wipe(&mut prefix);
    pk
}

/// Firma `msg` con la semilla (la firma es determinista).
pub fn sign(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    let (mut a, mut prefix) = expand(seed);
    let base = &consts().basepoint;
    let pk = base.mul_scalar(&a).compress();

    let mut hr = Sha512::new();
    hr.update(&prefix);
    hr.update(msg);
    let mut r_wide = hr.finalize();
    let mut r = reduce_bytes64(&r_wide);
    let big_r = base.mul_scalar(&r).compress();

    let mut hk = Sha512::new();
    hk.update(&big_r);
    hk.update(&pk);
    hk.update(msg);
    let k = reduce_bytes64(&hk.finalize());

    let s = scalar_mul_add(&k, &a, &r);

    wipe(&mut a);
    wipe(&mut prefix);
    wipe(&mut r_wide);
    wipe(&mut r);

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&big_r);
    sig[32..].copy_from_slice(&s);
    sig
}

/// Verificación estricta (ver el comentario del módulo).
pub fn verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let mut r_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&sig[..32]);
    s_bytes.copy_from_slice(&sig[32..]);
    if !scalar_is_canonical(&s_bytes) {
        return false;
    }
    let Some(a_pt) = decompress(pk) else { return false };
    if a_pt.mul_by_cofactor().is_identity() {
        return false; // clave de orden pequeño
    }
    let mut hk = Sha512::new();
    hk.update(&r_bytes);
    hk.update(pk);
    hk.update(msg);
    let k = reduce_bytes64(&hk.finalize());

    let sb = consts().basepoint.mul_scalar(&s_bytes);
    let ka = a_pt.mul_scalar(&k);
    let r_check = sb.add(&ka.neg());
    r_check.compress() == r_bytes
}

/// Par de claves. La semilla se borra al soltar el valor.
pub struct Keypair {
    seed: [u8; 32],
    public: [u8; 32],
}

impl Keypair {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let public = public_key_from_seed(&seed);
        Self { seed, public }
    }
    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        sign(&self.seed, msg)
    }
    /// Copia de la semilla (para respaldo). Quien la reciba debe borrarla con `wipe`.
    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }
}

impl Drop for Keypair {
    fn drop(&mut self) {
        wipe(&mut self.seed);
    }
}

impl core::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Keypair(público={:02x}{:02x}…, secreto oculto)", self.public[0], self.public[1])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }
    fn arr<const N: usize>(s: &str) -> [u8; N] {
        unhex(s).try_into().unwrap()
    }

    // RFC 8032 §7.1
    const RFC: [(&str, &str, &str, &str); 3] = [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
    ];

    #[test]
    fn rfc8032_vectors() {
        for (i, (sk, pk, msg, sig)) in RFC.iter().enumerate() {
            let seed: [u8; 32] = arr(sk);
            let msg = unhex(msg);
            let derived = public_key_from_seed(&seed);
            assert_eq!(derived.to_vec(), unhex(pk), "pk {i}");
            let s = sign(&seed, &msg);
            assert_eq!(s.to_vec(), unhex(sig), "sig {i}");
            assert!(verify(&derived, &msg, &s), "verify {i}");
        }
    }

    #[test]
    fn field_encoding_roundtrip_and_p_is_not_canonical() {
        // p y p+1 no son canónicos; 0 y 1 sí
        let mut p = [0xffu8; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        assert_ne!(Fe::from_bytes(&p).to_bytes(), p);
        assert_eq!(Fe::from_bytes(&p).to_bytes(), [0u8; 32]);
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(Fe::ONE.to_bytes(), one);
        // a * a^-1 = 1
        let x = Fe::from_bytes(&arr::<32>(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd0f",
        ));
        assert!(x.mul(&x.invert()).eq(&Fe::ONE));
        assert!(x.add(&x.neg()).eq(&Fe::ZERO));
    }

    #[test]
    fn scalar_reduction_basics() {
        // L mod L = 0 ; (L-1)+1 = 0 ; 1*1+0 = 1
        let l = from_limbs(&L);
        let mut wide = [0u64; 8];
        wide[..4].copy_from_slice(&L);
        assert_eq!(reduce_wide(&wide), [0; 4]);
        let one = {
            let mut o = [0u8; 32];
            o[0] = 1;
            o
        };
        let zero = [0u8; 32];
        assert_eq!(scalar_mul_add(&one, &one, &zero), one);
        assert!(!scalar_is_canonical(&l));
        let mut lm1 = L;
        lm1[0] -= 1;
        assert!(scalar_is_canonical(&from_limbs(&lm1)));
        assert_eq!(scalar_mul_add(&from_limbs(&lm1), &one, &one), zero);
    }

    #[test]
    fn group_order_kills_the_basepoint() {
        // [L]B = identidad y [L+1]B = B (L no cabe en 255 bits con clamping: se usa mul_scalar directo)
        let b = &consts().basepoint;
        let l = from_limbs(&L);
        assert!(b.mul_scalar(&l).is_identity());
        let mut l1 = L;
        l1[0] += 1;
        assert_eq!(b.mul_scalar(&from_limbs(&l1)).compress(), b.compress());
    }

    #[test]
    fn rejects_tampering() {
        let seed = [7u8; 32];
        let kp = Keypair::from_seed(seed);
        let msg = b"transferencia de prueba";
        let sig = kp.sign(msg);
        assert!(verify(&kp.public_key(), msg, &sig));
        // mensaje distinto
        assert!(!verify(&kp.public_key(), b"otra", &sig));
        // un bit cambiado en R, en S y en la clave
        for byte in [0usize, 31, 32, 40, 63] {
            let mut bad = sig;
            bad[byte] ^= 1;
            assert!(!verify(&kp.public_key(), msg, &bad), "byte {byte}");
        }
        let mut pk = kp.public_key();
        pk[5] ^= 1;
        assert!(!verify(&pk, msg, &sig));
        // otra clave
        let other = Keypair::from_seed([8u8; 32]);
        assert!(!verify(&other.public_key(), msg, &sig));
    }

    #[test]
    fn strict_verification_rules() {
        let kp = Keypair::from_seed([9u8; 32]);
        let msg = b"estricta";
        let sig = kp.sign(msg);

        // S + L: la misma firma "maleable" no se acepta
        let mut s = to_limbs(&arr::<32>(&sig[32..].iter().map(|b| format!("{b:02x}")).collect::<String>()));
        let mut carry = 0u128;
        for i in 0..4 {
            let t = s[i] as u128 + L[i] as u128 + carry;
            s[i] = t as u64;
            carry = t >> 64;
        }
        if carry == 0 {
            let mut mal = sig;
            mal[32..].copy_from_slice(&from_limbs(&s));
            assert!(!verify(&kp.public_key(), msg, &mal));
        }

        // clave de orden pequeño: la identidad (y=1) y el punto de orden 2 (y=-1)
        let mut ident = [0u8; 32];
        ident[0] = 1;
        assert!(!verify(&ident, msg, &sig));
        let mut order2 = [0xffu8; 32];
        order2[0] = 0xec;
        order2[31] = 0x7f;
        assert!(!verify(&order2, msg, &sig));

        // y >= p: codificación no canónica de la clave (y = p + 1 equivale a y = 1)
        let mut noncanon = [0xffu8; 32];
        noncanon[0] = 0xee;
        noncanon[31] = 0x7f;
        assert!(!verify(&noncanon, msg, &sig));
    }

    #[test]
    fn wipe_zeroes() {
        let mut b = [0xaau8; 40];
        wipe(&mut b);
        assert_eq!(b, [0u8; 40]);
    }
}
