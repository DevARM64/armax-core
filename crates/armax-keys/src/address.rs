//! Direcciones de ARMax.
//!
//! * La dirección de consenso (`armax_chain::Address`, 32 bytes) es `SHA-256("ARMAX-ADDR-v0" ‖ clave
//!   pública Ed25519)`: no revela la clave pública hasta que se gasta.
//! * Para personas se escribe en Bech32m (BIP-350): `arm1…`, con un byte de versión (0) y una suma de
//!   verificación que detecta cualquier error de 4 caracteres o menos y los cambios de mayúsculas.

use armax_chain::Address;
use armax_vm::sha256::sha256_cat;

/// Prefijo legible de las direcciones de la red principal.
pub const HRP: &str = "arm";
/// Versión del tipo de dirección (0 = hash de clave pública Ed25519).
pub const ADDRESS_VERSION: u8 = 0;

pub fn address_from_public_key(pk: &[u8; 32]) -> Address {
    Address(sha256_cat(&[b"ARMAX-ADDR-v0", pk]))
}

// ---- Bech32m -------------------------------------------------------------------------------

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST: u32 = 0x2bc8_30a3;

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut chk = 1u32;
    for v in values {
        let b = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ (*v as u32);
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut v: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
    v.push(0);
    v.extend(hrp.bytes().map(|c| c & 31));
    v
}

#[derive(Debug, PartialEq, Eq)]
pub enum AddressError {
    /// Cadena mal formada (longitud, caracteres, mayúsculas mezcladas, separador).
    Malformed(&'static str),
    /// La suma de verificación no coincide.
    BadChecksum,
    /// El prefijo no es `arm`.
    WrongPrefix,
    /// Versión de dirección desconocida.
    BadVersion(u8),
    /// El contenido no mide 32 bytes o el relleno no es cero.
    BadPayload,
}

impl core::fmt::Display for AddressError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for AddressError {}

/// Codifica `data` (grupos de 5 bits) con el prefijo `hrp` en Bech32m.
pub fn bech32m_encode(hrp: &str, data: &[u8]) -> String {
    let hrp = hrp.to_ascii_lowercase();
    let mut values = hrp_expand(&hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0u8; 6]);
    let pm = polymod(&values) ^ BECH32M_CONST;
    let mut s = hrp.clone();
    s.push('1');
    for d in data {
        s.push(CHARSET[*d as usize] as char);
    }
    for i in 0..6 {
        s.push(CHARSET[((pm >> (5 * (5 - i))) & 31) as usize] as char);
    }
    s
}

/// Decodifica una cadena Bech32m: devuelve (prefijo en minúsculas, datos de 5 bits sin la suma).
pub fn bech32m_decode(s: &str) -> Result<(String, Vec<u8>), AddressError> {
    if s.len() > 90 {
        return Err(AddressError::Malformed("más de 90 caracteres"));
    }
    if s.bytes().any(|c| !(33..=126).contains(&c)) {
        return Err(AddressError::Malformed("caracter fuera de rango"));
    }
    let has_lower = s.bytes().any(|c| c.is_ascii_lowercase());
    let has_upper = s.bytes().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(AddressError::Malformed("mayúsculas y minúsculas mezcladas"));
    }
    let s = s.to_ascii_lowercase();
    let pos = s.rfind('1').ok_or(AddressError::Malformed("falta el separador 1"))?;
    if pos < 1 {
        return Err(AddressError::Malformed("prefijo vacío"));
    }
    if s.len() - pos - 1 < 6 {
        return Err(AddressError::Malformed("suma de verificación incompleta"));
    }
    let hrp = &s[..pos];
    let mut data = Vec::with_capacity(s.len() - pos - 1);
    for c in s[pos + 1..].bytes() {
        let idx = CHARSET.iter().position(|x| *x == c).ok_or(AddressError::Malformed("caracter no válido"))?;
        data.push(idx as u8);
    }
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(&data);
    if polymod(&values) != BECH32M_CONST {
        return Err(AddressError::BadChecksum);
    }
    data.truncate(data.len() - 6);
    Ok((hrp.to_string(), data))
}

/// 8 bits → 5 bits (con relleno de ceros al final).
fn to_5bit(bytes: &[u8]) -> Vec<u8> {
    let (mut acc, mut bits) = (0u32, 0u32);
    let mut out = vec![];
    for b in bytes {
        acc = (acc << 8) | *b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        out.push(((acc << (5 - bits)) & 31) as u8);
    }
    out
}

/// 5 bits → 8 bits; el relleno sobrante debe ser menor de 5 bits y todo ceros.
fn from_5bit(groups: &[u8]) -> Option<Vec<u8>> {
    let (mut acc, mut bits) = (0u32, 0u32);
    let mut out = vec![];
    for g in groups {
        if *g > 31 {
            return None;
        }
        acc = (acc << 5) | *g as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if bits >= 5 || (acc << (8 - bits)) & 0xff != 0 {
        return None;
    }
    Some(out)
}

/// Dirección para personas: `arm1…`
pub fn encode(addr: &Address) -> String {
    let mut data = vec![ADDRESS_VERSION];
    data.extend(to_5bit(&addr.0));
    bech32m_encode(HRP, &data)
}

pub fn decode(s: &str) -> Result<Address, AddressError> {
    let (hrp, data) = bech32m_decode(s)?;
    if hrp != HRP {
        return Err(AddressError::WrongPrefix);
    }
    let (&version, rest) = data.split_first().ok_or(AddressError::BadPayload)?;
    if version != ADDRESS_VERSION {
        return Err(AddressError::BadVersion(version));
    }
    let bytes = from_5bit(rest).ok_or(AddressError::BadPayload)?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| AddressError::BadPayload)?;
    Ok(Address(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bip350_valid_strings_decode() {
        for s in [
            "A1LQFN3A",
            "a1lqfn3a",
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
            "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
            "?1v759aa",
            "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
        ] {
            assert!(bech32m_decode(s).is_ok(), "{s}");
        }
        let (hrp, data) = bech32m_decode("A1LQFN3A").unwrap();
        assert_eq!((hrp.as_str(), data.len()), ("a", 0));
    }

    #[test]
    fn bip350_invalid_strings_fail() {
        // checksum de Bech32 (BIP-173) no vale como Bech32m
        assert!(bech32m_decode("A12UEL5L").is_err());
        for s in [
            "\u{20}1xj0phk",  // prefijo con caracter fuera de rango
            "1qyrz8wqd2c9m",  // prefijo vacío
            "in1muywd",       // checksum demasiado corto
            "mm1crxm3i",      // caracter inválido en la suma
            "au1s5cgom",      // caracter inválido en la suma
            "M1VUXWEZ",       // suma calculada con el prefijo en mayúsculas
            "16plkw9",        // prefijo vacío
            "1p2gdwpf",       // prefijo vacío
        ] {
            assert!(bech32m_decode(s).is_err(), "{s:?}");
        }
        assert!(bech32m_decode("A1lqfn3A").is_err(), "mayúsculas mezcladas");
    }

    #[test]
    fn encode_matches_bip350_example() {
        assert_eq!(bech32m_encode("a", &[]), "a1lqfn3a");
        let (h, d) = bech32m_decode("abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx").unwrap();
        assert_eq!(bech32m_encode(&h, &d), "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx");
    }

    #[test]
    fn address_roundtrip_and_shape() {
        let a = address_from_public_key(&[5u8; 32]);
        let s = encode(&a);
        assert!(s.starts_with("arm1"));
        assert_eq!(s.len(), 4 + 53 + 6);
        assert_eq!(decode(&s), Ok(a));
        assert_eq!(decode(&s.to_ascii_uppercase()), Ok(a));
        assert_ne!(address_from_public_key(&[5u8; 32]), address_from_public_key(&[6u8; 32]));
    }

    #[test]
    fn every_single_character_error_is_detected() {
        let s = encode(&address_from_public_key(&[9u8; 32]));
        let chars: Vec<char> = s.chars().collect();
        for i in 0..chars.len() {
            for rep in CHARSET.iter().map(|c| *c as char) {
                if rep == chars[i] {
                    continue;
                }
                let mut t = chars.clone();
                t[i] = rep;
                let t: String = t.into_iter().collect();
                assert!(decode(&t).is_err(), "posición {i} -> {rep}");
            }
        }
    }

    #[test]
    fn rejects_other_prefix_version_and_length() {
        let a = address_from_public_key(&[1u8; 32]);
        // otro prefijo con suma válida
        let mut data = vec![ADDRESS_VERSION];
        data.extend(to_5bit(&a.0));
        assert_eq!(decode(&bech32m_encode("btc", &data)), Err(AddressError::WrongPrefix));
        // versión desconocida
        let mut d2 = vec![1u8];
        d2.extend(to_5bit(&a.0));
        assert_eq!(decode(&bech32m_encode(HRP, &d2)), Err(AddressError::BadVersion(1)));
        // 31 bytes
        let mut d3 = vec![0u8];
        d3.extend(to_5bit(&a.0[..31]));
        assert_eq!(decode(&bech32m_encode(HRP, &d3)), Err(AddressError::BadPayload));
        // relleno distinto de cero en el último grupo
        let mut d4 = vec![0u8];
        let mut g = to_5bit(&a.0);
        *g.last_mut().unwrap() |= 1;
        d4.extend(g);
        assert_eq!(decode(&bech32m_encode(HRP, &d4)), Err(AddressError::BadPayload));
        assert!(decode("").is_err());
    }
}
