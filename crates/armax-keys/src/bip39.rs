//! BIP-39: frase mnemónica ↔ entropía y semilla.
//!
//! La lista de 2048 palabras (`english.txt`) se comprueba contra el SHA-256 oficial del archivo
//! en los tests. La frase se guarda en una sola cadena con espacios simples y se borra al soltar.
//! La contraseña opcional se usa tal cual: para caracteres no ASCII debe llegar ya normalizada en
//! NFKD (esta biblioteca no trae tablas Unicode); con ASCII no hace falta nada.

use core::fmt;
use std::sync::OnceLock;

use armax_vm::sha256::sha256;

use crate::ed25519::wipe;
use crate::sha512::pbkdf2_hmac_sha512;

static WORDLIST_RAW: &str = include_str!("english.txt");

/// SHA-256 del archivo `english.txt` oficial de BIP-39 (con salto de línea final).
pub const WORDLIST_SHA256: [u8; 32] = [
    0x2f, 0x5e, 0xed, 0x53, 0xa4, 0x72, 0x7b, 0x4b, 0xf8, 0x88, 0x0d, 0x8f, 0x3f, 0x19, 0x9e, 0xfc, 0x90, 0xe5, 0x85,
    0x03, 0x64, 0x6d, 0x9f, 0xf8, 0xef, 0xf3, 0xa2, 0xed, 0x3b, 0x24, 0xdb, 0xda,
];

pub fn wordlist() -> &'static [&'static str] {
    static W: OnceLock<Vec<&'static str>> = OnceLock::new();
    W.get_or_init(|| {
        let v: Vec<&str> = WORDLIST_RAW.lines().collect();
        assert_eq!(v.len(), 2048, "la lista de palabras debe tener 2048 entradas");
        v
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum Bip39Error {
    /// Entropía de longitud no válida (16, 20, 24, 28 o 32 bytes).
    BadEntropyLength(usize),
    /// Número de palabras no válido (12, 15, 18, 21 o 24).
    BadWordCount(usize),
    /// La palabra en esa posición (empezando en 0) no está en la lista.
    UnknownWord(usize),
    /// La suma de verificación de la frase no coincide.
    BadChecksum,
}

impl fmt::Display for Bip39Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Bip39Error::BadEntropyLength(n) => write!(f, "entropía de {n} bytes no válida (16/20/24/28/32)"),
            Bip39Error::BadWordCount(n) => write!(f, "{n} palabras no válido (12/15/18/21/24)"),
            Bip39Error::UnknownWord(i) => write!(f, "la palabra {} no está en la lista", i + 1),
            Bip39Error::BadChecksum => write!(f, "suma de verificación incorrecta"),
        }
    }
}

impl std::error::Error for Bip39Error {}

pub struct Mnemonic {
    phrase: String,
}

fn get_bit(bytes: &[u8], i: usize) -> u8 {
    (bytes[i / 8] >> (7 - i % 8)) & 1
}

impl Mnemonic {
    /// Frase a partir de entropía (16, 20, 24, 28 o 32 bytes).
    pub fn from_entropy(entropy: &[u8]) -> Result<Mnemonic, Bip39Error> {
        let n = entropy.len();
        if !matches!(n, 16 | 20 | 24 | 28 | 32) {
            return Err(Bip39Error::BadEntropyLength(n));
        }
        let cs_bits = n * 8 / 32;
        let hash = sha256(entropy);
        let total = n * 8 + cs_bits;
        let words = wordlist();
        let mut phrase = String::new();
        for w in 0..total / 11 {
            let mut idx = 0usize;
            for b in 0..11 {
                let pos = w * 11 + b;
                let bit = if pos < n * 8 { get_bit(entropy, pos) } else { get_bit(&hash, pos - n * 8) };
                idx = (idx << 1) | bit as usize;
            }
            if w > 0 {
                phrase.push(' ');
            }
            phrase.push_str(words[idx]);
        }
        Ok(Mnemonic { phrase })
    }

    /// Valida una frase escrita por el usuario (mayúsculas y espacios de más se toleran).
    pub fn from_phrase(phrase: &str) -> Result<Mnemonic, Bip39Error> {
        let words = wordlist();
        let parts: Vec<String> = phrase.split_whitespace().map(|w| w.to_lowercase()).collect();
        let count = parts.len();
        if !matches!(count, 12 | 15 | 18 | 21 | 24) {
            return Err(Bip39Error::BadWordCount(count));
        }
        let mut bits: Vec<u8> = Vec::with_capacity(count * 11);
        for (i, p) in parts.iter().enumerate() {
            let idx = words.binary_search(&p.as_str()).map_err(|_| Bip39Error::UnknownWord(i))?;
            for b in (0..11).rev() {
                bits.push(((idx >> b) & 1) as u8);
            }
        }
        let ent_bits = count * 11 * 32 / 33;
        let mut entropy = vec![0u8; ent_bits / 8];
        for i in 0..ent_bits {
            entropy[i / 8] |= bits[i] << (7 - i % 8);
        }
        let hash = sha256(&entropy);
        let ok = (0..bits.len() - ent_bits).all(|i| bits[ent_bits + i] == get_bit(&hash, i));
        wipe(&mut entropy);
        if !ok {
            return Err(Bip39Error::BadChecksum);
        }
        Ok(Mnemonic { phrase: parts.join(" ") })
    }

    pub fn phrase(&self) -> &str {
        &self.phrase
    }

    pub fn word_count(&self) -> usize {
        self.phrase.split(' ').count()
    }

    /// Entropía original (el llamador debe borrarla con `wipe`).
    pub fn to_entropy(&self) -> Vec<u8> {
        let words = wordlist();
        let count = self.word_count();
        let ent_bits = count * 11 * 32 / 33;
        let mut entropy = vec![0u8; ent_bits / 8];
        let mut pos = 0usize;
        for w in self.phrase.split(' ') {
            let idx = words.binary_search(&w).expect("la frase se validó al crearla");
            for b in (0..11).rev() {
                if pos < ent_bits {
                    entropy[pos / 8] |= (((idx >> b) & 1) as u8) << (7 - pos % 8);
                }
                pos += 1;
            }
        }
        entropy
    }

    /// Semilla de 64 bytes: PBKDF2-HMAC-SHA512(frase, "mnemonic" + contraseña, 2048).
    pub fn to_seed(&self, passphrase: &str) -> [u8; 64] {
        let mut salt = String::from("mnemonic");
        salt.push_str(passphrase);
        let mut out = [0u8; 64];
        pbkdf2_hmac_sha512(self.phrase.as_bytes(), salt.as_bytes(), 2048, &mut out);
        // SAFETY: se escriben ceros, que son UTF-8 válido.
        wipe(unsafe { salt.as_bytes_mut() });
        out
    }
}

impl Drop for Mnemonic {
    fn drop(&mut self) {
        // SAFETY: se escriben ceros, que son UTF-8 válido.
        wipe(unsafe { self.phrase.as_bytes_mut() });
    }
}

impl fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mnemonic({} palabras, oculto)", self.word_count())
    }
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

    #[test]
    fn wordlist_is_the_official_one() {
        assert_eq!(sha256(WORDLIST_RAW.as_bytes()), WORDLIST_SHA256);
        let w = wordlist();
        assert_eq!(w.len(), 2048);
        assert_eq!((w[0], w[2047]), ("abandon", "zoo"));
        assert!(w.windows(2).all(|p| p[0] < p[1]), "ordenada y sin repetidas");
        let mut prefixes: Vec<&str> = w.iter().map(|x| &x[..x.len().min(4)]).collect();
        prefixes.sort();
        prefixes.dedup();
        assert_eq!(prefixes.len(), 2048, "los 4 primeros caracteres identifican cada palabra");
    }

    // Vectores oficiales de BIP-39 (trezor/python-mnemonic vectors.json), contraseña "TREZOR".
    const VECTORS: [(&str, &str, &str); 6] = [
        (
            "00000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
        ),
        (
            "80808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
            "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
        ),
        (
            "ffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
        ),
        (
            "000000000000000000000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
            "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
        ),
    ];

    #[test]
    fn official_vectors() {
        for (ent, phrase, seed) in VECTORS {
            let m = Mnemonic::from_entropy(&unhex(ent)).unwrap();
            assert_eq!(m.phrase(), phrase);
            assert_eq!(hex(&m.to_entropy()), ent);
            assert_eq!(hex(&m.to_seed("TREZOR")), seed, "{phrase}");
            let back = Mnemonic::from_phrase(phrase).unwrap();
            assert_eq!(back.phrase(), phrase);
        }
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(Mnemonic::from_entropy(&[0u8; 15]).unwrap_err(), Bip39Error::BadEntropyLength(15));
        assert_eq!(Mnemonic::from_phrase("abandon abandon").unwrap_err(), Bip39Error::BadWordCount(2));
        // checksum incorrecto: última palabra cambiada
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert_eq!(Mnemonic::from_phrase(bad).unwrap_err(), Bip39Error::BadChecksum);
        // palabra desconocida (posición 3)
        let unk = "abandon abandon abandon xyzzy abandon abandon abandon abandon abandon abandon abandon about";
        assert_eq!(Mnemonic::from_phrase(unk).unwrap_err(), Bip39Error::UnknownWord(3));
        // tolera mayúsculas y espacios de más
        let m = Mnemonic::from_phrase("  LEGAL winner  thank year wave sausage worth useful legal winner thank YELLOW ").unwrap();
        assert_eq!(m.phrase(), "legal winner thank year wave sausage worth useful legal winner thank yellow");
    }

    #[test]
    fn passphrase_changes_the_seed() {
        let m = Mnemonic::from_entropy(&[1u8; 16]).unwrap();
        assert_ne!(m.to_seed(""), m.to_seed("x"));
        assert_eq!(m.to_seed("x"), m.to_seed("x"));
    }
}
