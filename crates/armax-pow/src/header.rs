//! Cabecera de bloque y su serialización canónica.
//!
//! Formato fijo de 124 bytes (enteros little-endian; hashes crudos; target big-endian
//! para que sea directamente comparable con el digest del PoW):
//!
//! | offset | len | campo        |
//! |--------|-----|--------------|
//! | 0      | 4   | version (u32)|
//! | 4      | 8   | height (u64) |
//! | 12     | 32  | prev_hash    |
//! | 44     | 32  | merkle_root  |
//! | 76     | 8   | timestamp (u64, segundos Unix) |
//! | 84     | 32  | target (U256, big-endian)      |
//! | 116    | 8   | nonce (u64)  |
//!
//! La entrada del PoW son exactamente estos 124 bytes (nonce incluido). El `id` del
//! bloque es un hash barato de los mismos bytes: enlazar bloques o servir cabeceras
//! no cuesta una ejecución de la VM.

use armax_vm::sha256::sha256_cat;

use crate::u256::U256;

pub const HEADER_LEN: usize = 124;
pub const NONCE_OFFSET: usize = 116;

pub type Hash32 = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: u32,
    pub height: u64,
    pub prev_hash: Hash32,
    pub merkle_root: Hash32,
    pub timestamp: u64,
    pub target: U256,
    pub nonce: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    BadLength { expected: usize, got: usize },
}

impl BlockHeader {
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0..4].copy_from_slice(&self.version.to_le_bytes());
        b[4..12].copy_from_slice(&self.height.to_le_bytes());
        b[12..44].copy_from_slice(&self.prev_hash);
        b[44..76].copy_from_slice(&self.merkle_root);
        b[76..84].copy_from_slice(&self.timestamp.to_le_bytes());
        b[84..116].copy_from_slice(&self.target.to_be_bytes());
        b[NONCE_OFFSET..HEADER_LEN].copy_from_slice(&self.nonce.to_le_bytes());
        b
    }

    /// Decodificación estricta: la longitud debe ser exactamente `HEADER_LEN`.
    /// La codificación es biyectiva, así que `from_bytes(to_bytes(h)) == h` y no hay
    /// dos representaciones válidas de la misma cabecera.
    pub fn from_bytes(b: &[u8]) -> Result<Self, DecodeError> {
        if b.len() != HEADER_LEN {
            return Err(DecodeError::BadLength { expected: HEADER_LEN, got: b.len() });
        }
        Ok(Self {
            version: u32::from_le_bytes(b[0..4].try_into().unwrap()),
            height: u64::from_le_bytes(b[4..12].try_into().unwrap()),
            prev_hash: b[12..44].try_into().unwrap(),
            merkle_root: b[44..76].try_into().unwrap(),
            timestamp: u64::from_le_bytes(b[76..84].try_into().unwrap()),
            target: U256::from_be_bytes(b[84..116].try_into().unwrap()),
            nonce: u64::from_le_bytes(b[NONCE_OFFSET..HEADER_LEN].try_into().unwrap()),
        })
    }

    /// Identificador del bloque (hash barato, separado por dominio del digest del PoW).
    pub fn id(&self) -> Hash32 {
        sha256_cat(&[b"ARMAX-BLOCKID-v0", &self.to_bytes()])
    }

    pub fn with_nonce(&self, nonce: u64) -> Self {
        let mut h = self.clone();
        h.nonce = nonce;
        h
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> BlockHeader {
        BlockHeader {
            version: 1,
            height: 0x0102_0304_0506_0708,
            prev_hash: [0xAA; 32],
            merkle_root: [0xBB; 32],
            timestamp: 1_800_000_000,
            target: U256::pow2(250).unwrap(),
            nonce: 0xDEAD_BEEF_0000_0001,
        }
    }

    #[test]
    fn fixed_length_and_roundtrip() {
        let h = sample();
        let b = h.to_bytes();
        assert_eq!(b.len(), 124);
        assert_eq!(BlockHeader::from_bytes(&b).unwrap(), h);
    }

    #[test]
    fn field_offsets_and_endianness() {
        let b = sample().to_bytes();
        assert_eq!(&b[0..4], &[1, 0, 0, 0]); // version LE
        assert_eq!(&b[4..12], &[8, 7, 6, 5, 4, 3, 2, 1]); // height LE
        assert_eq!(&b[12..44], &[0xAA; 32]);
        assert_eq!(&b[44..76], &[0xBB; 32]);
        // 2^250 en big-endian: el byte 0 guarda los bits 255..248, así que vale 1<<2 = 0x04
        assert_eq!(b[84], 0x04);
        assert!(b[85..116].iter().all(|&x| x == 0));
        assert_eq!(&b[NONCE_OFFSET..], &0xDEAD_BEEF_0000_0001u64.to_le_bytes());
    }

    #[test]
    fn strict_length() {
        let b = sample().to_bytes();
        assert_eq!(
            BlockHeader::from_bytes(&b[..123]),
            Err(DecodeError::BadLength { expected: 124, got: 123 })
        );
        let mut long = b.to_vec();
        long.push(0);
        assert!(BlockHeader::from_bytes(&long).is_err());
    }

    #[test]
    fn id_depends_on_every_field() {
        let base = sample();
        let id = base.id();
        let mut variants = vec![];
        let mut h = base.clone();
        h.version ^= 1;
        variants.push(h);
        let mut h = base.clone();
        h.height ^= 1;
        variants.push(h);
        let mut h = base.clone();
        h.prev_hash[31] ^= 1;
        variants.push(h);
        let mut h = base.clone();
        h.merkle_root[0] ^= 1;
        variants.push(h);
        let mut h = base.clone();
        h.timestamp ^= 1;
        variants.push(h);
        let mut h = base.clone();
        h.target = h.target.checked_add(U256::ONE).unwrap();
        variants.push(h);
        variants.push(base.with_nonce(base.nonce ^ 1));
        for v in variants {
            assert_ne!(v.id(), id);
        }
    }
}
