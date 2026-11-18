//! Primitivas AES para la VM y el generador de scratchpad.
//!
//! Orden de bytes: el estado es de 16 bytes en el orden de FIPS-197
//! (`s[4*columna + fila]`), idéntico al de `vaeseq_u8` en ARM64.
//!
//! La VM solo usa dos operaciones, con la semántica de AES-NI (`aesenc`/`aesdec`):
//!   * `enc_round(s, rk) = MixColumns(SubBytes(ShiftRows(s))) ^ rk`
//!   * `dec_round(s, rk) = InvMixColumns(InvSubBytes(InvShiftRows(s))) ^ rk`
//!
//! `Portable` las implementa en software (validado con FIPS-197 en los tests);
//! `Neon` las implementa con intrínsecos de ARM64 y debe producir bytes idénticos.

pub type State = [u8; 16];

const fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    let mut i = 0;
    while i < 8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
        i += 1;
    }
    p
}

const fn build_sbox() -> [u8; 256] {
    let mut s = [0u8; 256];
    let mut x = 0usize;
    while x < 256 {
        // Inverso multiplicativo en GF(2^8): x^254 (0 -> 0).
        let mut inv = 0u8;
        if x != 0 {
            inv = 1;
            let mut base = x as u8;
            let mut e = 254u32;
            while e > 0 {
                if e & 1 == 1 {
                    inv = gmul(inv, base);
                }
                base = gmul(base, base);
                e >>= 1;
            }
        }
        let b = inv;
        s[x] = b ^ b.rotate_left(1) ^ b.rotate_left(2) ^ b.rotate_left(3) ^ b.rotate_left(4) ^ 0x63;
        x += 1;
    }
    s
}

const fn build_inv_sbox() -> [u8; 256] {
    let s = build_sbox();
    let mut inv = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        inv[s[i] as usize] = i as u8;
        i += 1;
    }
    inv
}

pub static SBOX: [u8; 256] = build_sbox();
pub static INV_SBOX: [u8; 256] = build_inv_sbox();

#[inline(always)]
pub fn xor16(a: State, b: State) -> State {
    let mut o = a;
    for i in 0..16 {
        o[i] ^= b[i];
    }
    o
}

#[inline(always)]
fn shift_rows(s: &State) -> State {
    let mut o = [0u8; 16];
    for c in 0..4 {
        for r in 0..4 {
            o[4 * c + r] = s[4 * ((c + r) % 4) + r];
        }
    }
    o
}

#[inline(always)]
fn inv_shift_rows(s: &State) -> State {
    let mut o = [0u8; 16];
    for c in 0..4 {
        for r in 0..4 {
            o[4 * ((c + r) % 4) + r] = s[4 * c + r];
        }
    }
    o
}

#[inline(always)]
fn xtime(a: u8) -> u8 {
    (a << 1) ^ ((a >> 7) * 0x1b)
}

/// Equivalente de `vaeseq_u8(data, key)`: SubBytes(ShiftRows(data ^ key)).
pub fn aese(data: State, key: State) -> State {
    let t = shift_rows(&xor16(data, key));
    let mut o = [0u8; 16];
    for i in 0..16 {
        o[i] = SBOX[t[i] as usize];
    }
    o
}

/// Equivalente de `vaesmcq_u8`: MixColumns.
pub fn aesmc(s: State) -> State {
    let mut o = [0u8; 16];
    for c in 0..4 {
        let a = [s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]];
        o[4 * c] = xtime(a[0]) ^ xtime(a[1]) ^ a[1] ^ a[2] ^ a[3];
        o[4 * c + 1] = a[0] ^ xtime(a[1]) ^ xtime(a[2]) ^ a[2] ^ a[3];
        o[4 * c + 2] = a[0] ^ a[1] ^ xtime(a[2]) ^ xtime(a[3]) ^ a[3];
        o[4 * c + 3] = xtime(a[0]) ^ a[0] ^ a[1] ^ a[2] ^ xtime(a[3]);
    }
    o
}

/// Equivalente de `vaesdq_u8(data, key)`: InvSubBytes(InvShiftRows(data ^ key)).
pub fn aesd(data: State, key: State) -> State {
    let t = inv_shift_rows(&xor16(data, key));
    let mut o = [0u8; 16];
    for i in 0..16 {
        o[i] = INV_SBOX[t[i] as usize];
    }
    o
}

/// Equivalente de `vaesimcq_u8`: InvMixColumns.
pub fn aesimc(s: State) -> State {
    let mut o = [0u8; 16];
    for c in 0..4 {
        let a = [s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]];
        o[4 * c] = gmul(a[0], 14) ^ gmul(a[1], 11) ^ gmul(a[2], 13) ^ gmul(a[3], 9);
        o[4 * c + 1] = gmul(a[0], 9) ^ gmul(a[1], 14) ^ gmul(a[2], 11) ^ gmul(a[3], 13);
        o[4 * c + 2] = gmul(a[0], 13) ^ gmul(a[1], 9) ^ gmul(a[2], 14) ^ gmul(a[3], 11);
        o[4 * c + 3] = gmul(a[0], 11) ^ gmul(a[1], 13) ^ gmul(a[2], 9) ^ gmul(a[3], 14);
    }
    o
}

/// Backend de las dos rondas AES que consume la VM.
pub trait Aes {
    const NAME: &'static str;
    fn enc_round(s: State, rk: State) -> State;
    fn dec_round(s: State, rk: State) -> State;
}

/// Implementación en software, válida en cualquier arquitectura.
#[derive(Clone, Copy, Debug)]
pub struct Portable;

impl Aes for Portable {
    const NAME: &'static str = "portable";

    #[inline]
    fn enc_round(s: State, rk: State) -> State {
        xor16(aesmc(aese(s, [0u8; 16])), rk)
    }

    #[inline]
    fn dec_round(s: State, rk: State) -> State {
        xor16(aesimc(aesd(s, [0u8; 16])), rk)
    }
}

/// Backend ARM64 con intrínsecos de hardware (requiere `target-feature=+aes`).
#[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
mod neon {
    use super::{Aes, State};
    use core::arch::aarch64::*;

    #[derive(Clone, Copy, Debug)]
    pub struct Neon;

    #[allow(unused_unsafe)]
    impl Aes for Neon {
        const NAME: &'static str = "aarch64-neon-aes";

        #[inline(always)]
        fn enc_round(s: State, rk: State) -> State {
            unsafe {
                let d = vld1q_u8(s.as_ptr());
                let k = vld1q_u8(rk.as_ptr());
                // aese con clave cero = SubBytes+ShiftRows; aesmc = MixColumns; luego XOR de rk.
                let r = veorq_u8(vaesmcq_u8(vaeseq_u8(d, vdupq_n_u8(0))), k);
                let mut out = [0u8; 16];
                vst1q_u8(out.as_mut_ptr(), r);
                out
            }
        }

        #[inline(always)]
        fn dec_round(s: State, rk: State) -> State {
            unsafe {
                let d = vld1q_u8(s.as_ptr());
                let k = vld1q_u8(rk.as_ptr());
                let r = veorq_u8(vaesimcq_u8(vaesdq_u8(d, vdupq_n_u8(0))), k);
                let mut out = [0u8; 16];
                vst1q_u8(out.as_mut_ptr(), r);
                out
            }
        }
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
pub use neon::Neon;

/// Backend que usa el nodo: hardware en ARM64 compilado con `+aes`, software en el resto.
#[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
pub type Native = Neon;
#[cfg(not(all(target_arch = "aarch64", target_feature = "aes")))]
pub type Native = Portable;

/// ¿Puede este CPU ejecutar el backend nativo? Comprobar al arrancar antes de minar.
pub fn native_aes_available() -> bool {
    #[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
    {
        std::arch::is_aarch64_feature_detected!("aes")
    }
    #[cfg(not(all(target_arch = "aarch64", target_feature = "aes")))]
    {
        true // el backend portable siempre funciona
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> State {
        let mut o = [0u8; 16];
        for i in 0..16 {
            o[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        o
    }

    fn expand_key(key: State) -> [State; 11] {
        let rcon = [0x01u8, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
        let mut w = [[0u8; 4]; 44];
        for i in 0..4 {
            w[i].copy_from_slice(&key[4 * i..4 * i + 4]);
        }
        for i in 4..44 {
            let mut t = w[i - 1];
            if i % 4 == 0 {
                t = [t[1], t[2], t[3], t[0]];
                for b in t.iter_mut() {
                    *b = SBOX[*b as usize];
                }
                t[0] ^= rcon[i / 4 - 1];
            }
            for j in 0..4 {
                w[i][j] = w[i - 4][j] ^ t[j];
            }
        }
        let mut rk = [[0u8; 16]; 11];
        for r in 0..11 {
            for c in 0..4 {
                rk[r][4 * c..4 * c + 4].copy_from_slice(&w[4 * r + c]);
            }
        }
        rk
    }

    #[test]
    fn sbox_known_values() {
        assert_eq!(SBOX[0x00], 0x63);
        assert_eq!(SBOX[0x01], 0x7c);
        assert_eq!(SBOX[0x53], 0xed);
        assert_eq!(SBOX[0xff], 0x16);
        for i in 0..256 {
            assert_eq!(INV_SBOX[SBOX[i] as usize] as usize, i);
        }
    }

    // FIPS-197, Apéndice C.1 (AES-128).
    const KEY: &str = "000102030405060708090a0b0c0d0e0f";
    const PT: &str = "00112233445566778899aabbccddeeff";
    const CT: &str = "69c4e0d86a7b0430d8cdb78070b4c55a";

    fn encrypt<B: Aes>(pt: State, rk: &[State; 11]) -> State {
        let mut s = xor16(pt, rk[0]);
        for r in 1..10 {
            s = B::enc_round(s, rk[r]);
        }
        xor16(aese(s, [0u8; 16]), rk[10])
    }

    fn decrypt<B: Aes>(ct: State, rk: &[State; 11]) -> State {
        let mut s = xor16(ct, rk[10]);
        for r in (1..10).rev() {
            s = B::dec_round(s, aesimc(rk[r]));
        }
        xor16(aesd(s, [0u8; 16]), rk[0])
    }

    #[test]
    fn fips197_portable() {
        let rk = expand_key(h(KEY));
        assert_eq!(encrypt::<Portable>(h(PT), &rk), h(CT));
        assert_eq!(decrypt::<Portable>(h(CT), &rk), h(PT));
    }

    #[test]
    fn native_matches_portable() {
        // En x86 Native == Portable (trivial); en ARM64 con +aes compara hardware vs software.
        let mut x: u64 = 0x1234_5678_9abc_def0;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..20_000 {
            let mut s = [0u8; 16];
            let mut k = [0u8; 16];
            s[..8].copy_from_slice(&next().to_le_bytes());
            s[8..].copy_from_slice(&next().to_le_bytes());
            k[..8].copy_from_slice(&next().to_le_bytes());
            k[8..].copy_from_slice(&next().to_le_bytes());
            assert_eq!(Native::enc_round(s, k), Portable::enc_round(s, k));
            assert_eq!(Native::dec_round(s, k), Portable::dec_round(s, k));
        }
    }
}
