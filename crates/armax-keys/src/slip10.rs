//! SLIP-0010 para Ed25519: derivación jerárquica (solo índices endurecidos, como exige la curva).
//!
//! Ruta de ARMax: `m/44'/1095520600'/cuenta'/0'/índice'`. El tipo de moneda 1095520600 es el
//! código ASCII "ARMX" (0x41524D58) y **no está registrado en SLIP-44**: es provisional hasta que se
//! decida registrarlo o elegir otro valor antes del lanzamiento.

use crate::ed25519::{wipe, Keypair};
use crate::sha512::hmac_sha512_cat;

pub const HARDENED: u32 = 0x8000_0000;
pub const ARMAX_COIN_TYPE: u32 = 0x4152_4D58;

#[derive(Debug, PartialEq, Eq)]
pub enum Slip10Error {
    /// Semilla fuera de 16..=64 bytes.
    BadSeedLength(usize),
    /// Índice sin el bit de "endurecido" (Ed25519 solo admite hijos endurecidos).
    NotHardened(u32),
    /// Ruta mal escrita.
    BadPath,
}

impl core::fmt::Display for Slip10Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Slip10Error {}

pub struct ExtKey {
    key: [u8; 32],
    chain: [u8; 32],
}

impl ExtKey {
    /// Clave maestra de una semilla (típicamente los 64 bytes de BIP-39).
    pub fn master(seed: &[u8]) -> Result<ExtKey, Slip10Error> {
        if !(16..=64).contains(&seed.len()) {
            return Err(Slip10Error::BadSeedLength(seed.len()));
        }
        let mut i = hmac_sha512_cat(b"ed25519 seed", &[seed]);
        let k = Self::split(&i);
        wipe(&mut i);
        Ok(k)
    }

    fn split(i: &[u8; 64]) -> ExtKey {
        let mut key = [0u8; 32];
        let mut chain = [0u8; 32];
        key.copy_from_slice(&i[..32]);
        chain.copy_from_slice(&i[32..]);
        ExtKey { key, chain }
    }

    /// Hijo endurecido: `index` debe traer el bit 31 puesto.
    pub fn derive(&self, index: u32) -> Result<ExtKey, Slip10Error> {
        if index & HARDENED == 0 {
            return Err(Slip10Error::NotHardened(index));
        }
        let mut i = hmac_sha512_cat(&self.chain, &[&[0u8], &self.key, &index.to_be_bytes()]);
        let k = Self::split(&i);
        wipe(&mut i);
        Ok(k)
    }

    /// Deriva una ruta de índices (cada uno con el bit 31 puesto).
    pub fn derive_path(&self, path: &[u32]) -> Result<ExtKey, Slip10Error> {
        let mut cur = ExtKey { key: self.key, chain: self.chain };
        for &i in path {
            cur = cur.derive(i)?;
        }
        Ok(cur)
    }

    /// Par de claves Ed25519 cuya semilla es la clave privada SLIP-0010.
    pub fn keypair(&self) -> Keypair {
        Keypair::from_seed(self.key)
    }

    pub fn chain_code(&self) -> [u8; 32] {
        self.chain
    }
    pub fn private_key(&self) -> [u8; 32] {
        self.key
    }
}

impl core::fmt::Debug for ExtKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ExtKey(oculto)")
    }
}

impl Drop for ExtKey {
    fn drop(&mut self) {
        wipe(&mut self.key);
        wipe(&mut self.chain);
    }
}

/// Ruta de cuenta de ARMax: `m/44'/ARMAX'/account'/0'/index'`.
pub fn armax_path(account: u32, index: u32) -> [u32; 5] {
    [44 | HARDENED, ARMAX_COIN_TYPE | HARDENED, account | HARDENED, HARDENED, index | HARDENED]
}

/// Lee una ruta como `m/44'/0'/1'` (todos los índices deben ser endurecidos).
pub fn parse_path(s: &str) -> Result<Vec<u32>, Slip10Error> {
    let mut parts = s.split('/');
    if parts.next() != Some("m") {
        return Err(Slip10Error::BadPath);
    }
    let mut out = vec![];
    for p in parts {
        let digits = p.strip_suffix('\'').or_else(|| p.strip_suffix('h')).ok_or(Slip10Error::BadPath)?;
        let n: u32 = digits.parse().map_err(|_| Slip10Error::BadPath)?;
        if n & HARDENED != 0 {
            return Err(Slip10Error::BadPath);
        }
        out.push(n | HARDENED);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // SLIP-0010, vector de prueba 1 de Ed25519 (semilla 000102…0f).
    #[test]
    fn slip10_official_vector_1() {
        let seed = unhex("000102030405060708090a0b0c0d0e0f");
        let m = ExtKey::master(&seed).unwrap();
        assert_eq!(hex(&m.chain_code()), "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb");
        assert_eq!(hex(&m.private_key()), "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7");
        assert_eq!(
            hex(&m.keypair().public_key()),
            "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"
        );
        let c = m.derive_path(&parse_path("m/0'").unwrap()).unwrap();
        assert_eq!(hex(&c.chain_code()), "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69");
        assert_eq!(hex(&c.private_key()), "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3");
        let c = m.derive_path(&parse_path("m/0'/1'").unwrap()).unwrap();
        assert_eq!(hex(&c.chain_code()), "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14");
        assert_eq!(hex(&c.private_key()), "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2");
    }

    #[test]
    fn rejects_non_hardened_and_bad_seeds() {
        let m = ExtKey::master(&[1u8; 32]).unwrap();
        assert_eq!(m.derive(5).unwrap_err(), Slip10Error::NotHardened(5));
        assert_eq!(ExtKey::master(&[1u8; 15]).unwrap_err(), Slip10Error::BadSeedLength(15));
        assert_eq!(ExtKey::master(&[1u8; 65]).unwrap_err(), Slip10Error::BadSeedLength(65));
        assert_eq!(parse_path("m/0").unwrap_err(), Slip10Error::BadPath);
        assert_eq!(parse_path("x/0'").unwrap_err(), Slip10Error::BadPath);
        assert_eq!(parse_path("m/2147483648'").unwrap_err(), Slip10Error::BadPath);
        assert_eq!(parse_path("m/44'/1h").unwrap(), vec![44 | HARDENED, 1 | HARDENED]);
        assert_eq!(parse_path("m").unwrap(), Vec::<u32>::new());
    }

    #[test]
    fn armax_path_is_all_hardened_and_distinct() {
        let p = armax_path(0, 0);
        assert!(p.iter().all(|i| i & HARDENED != 0));
        assert_eq!(p[1] & !HARDENED, ARMAX_COIN_TYPE);
        assert_ne!(armax_path(0, 0), armax_path(0, 1));
        let m = ExtKey::master(&[3u8; 64]).unwrap();
        let a = m.derive_path(&armax_path(0, 0)).unwrap().keypair().public_key();
        let b = m.derive_path(&armax_path(0, 1)).unwrap().keypair().public_key();
        assert_ne!(a, b);
    }
}
