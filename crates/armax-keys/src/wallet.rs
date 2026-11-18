//! Cartera: la semilla nunca se guarda en claro; solo se persiste la **entropía sellada** por una
//! `SecretVault`.
//!
//! En Android, `SecretVault` la implementa el puente Kotlin/Rust (UniFFI) con una clave AES-GCM
//! **no exportable** del Android Keystore (respaldada por TEE o StrongBox cuando el equipo la
//! tenga), opcionalmente atada a la autenticación del usuario. Ed25519 no se firma dentro del
//! Keystore (no hay soporte generalizado): la clave de firma se deriva en memoria al desbloquear,
//! se usa y se borra. La frase mnemónica se muestra una sola vez al crear la cartera, para el
//! respaldo en papel; después solo se puede recuperar con el respaldo, no desde el sellado.
//!
//! `InsecureTestVault` es solo para pruebas y herramientas locales.

use core::fmt;

use armax_chain::Address;
use armax_vm::sha256::sha256_cat;

use crate::address::address_from_public_key;
use crate::bip39::{Bip39Error, Mnemonic};
use crate::ed25519::{wipe, Keypair};
use crate::slip10::{armax_path, ExtKey, Slip10Error};

#[derive(Debug, PartialEq, Eq)]
pub enum VaultError {
    /// El Keystore rechazó la operación (bloqueado, clave invalidada, usuario canceló…).
    Unavailable(String),
    /// El sellado está dañado o no corresponde a esta bóveda.
    Corrupt,
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for VaultError {}

/// Sella y abre secretos con una clave que no sale del almacén seguro del dispositivo.
pub trait SecretVault {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, VaultError>;
    fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, VaultError>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum WalletError {
    Vault(VaultError),
    Mnemonic(Bip39Error),
    Derivation(Slip10Error),
}

impl From<VaultError> for WalletError {
    fn from(e: VaultError) -> Self {
        WalletError::Vault(e)
    }
}
impl From<Bip39Error> for WalletError {
    fn from(e: Bip39Error) -> Self {
        WalletError::Mnemonic(e)
    }
}
impl From<Slip10Error> for WalletError {
    fn from(e: Slip10Error) -> Self {
        WalletError::Derivation(e)
    }
}
impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for WalletError {}

pub struct Wallet<V: SecretVault> {
    vault: V,
    sealed_entropy: Vec<u8>,
}

impl<V: SecretVault> Wallet<V> {
    /// Crea una cartera nueva con `entropy` (16 o 32 bytes recomendados: 12 o 24 palabras) y
    /// devuelve la frase para el respaldo. La aplicación debe mostrarla una vez y no guardarla.
    pub fn create(vault: V, entropy: &[u8]) -> Result<(Wallet<V>, Mnemonic), WalletError> {
        let mnemonic = Mnemonic::from_entropy(entropy)?;
        let sealed_entropy = vault.seal(entropy)?;
        Ok((Wallet { vault, sealed_entropy }, mnemonic))
    }

    /// Restaura desde una frase de respaldo (en un teléfono nuevo, con su propia bóveda).
    pub fn restore(vault: V, mnemonic: &Mnemonic) -> Result<Wallet<V>, WalletError> {
        let mut entropy = mnemonic.to_entropy();
        let sealed = vault.seal(&entropy);
        wipe(&mut entropy);
        Ok(Wallet { vault, sealed_entropy: sealed? })
    }

    /// Reabre una cartera cuyo sellado ya guardó la aplicación.
    pub fn from_sealed(vault: V, sealed_entropy: Vec<u8>) -> Wallet<V> {
        Wallet { vault, sealed_entropy }
    }

    /// Bloque sellado que la aplicación debe persistir (inútil sin la bóveda del dispositivo).
    pub fn sealed(&self) -> &[u8] {
        &self.sealed_entropy
    }

    /// Deriva la llave `m/44'/ARMX'/account'/0'/index'`. `passphrase` es la contraseña BIP-39
    /// opcional ("" si no se usa); no se guarda en ningún lado.
    pub fn keypair(&self, passphrase: &str, account: u32, index: u32) -> Result<Keypair, WalletError> {
        let mut entropy = self.vault.open(&self.sealed_entropy)?;
        let mnemonic = Mnemonic::from_entropy(&entropy);
        wipe(&mut entropy);
        let mut seed = mnemonic?.to_seed(passphrase);
        let master = ExtKey::master(&seed);
        wipe(&mut seed);
        let child = master?.derive_path(&armax_path(account, index))?;
        Ok(child.keypair())
    }

    pub fn address(&self, passphrase: &str, account: u32, index: u32) -> Result<Address, WalletError> {
        Ok(address_from_public_key(&self.keypair(passphrase, account, index)?.public_key()))
    }
}

/// Bóveda de juguete: cifrado de flujo con SHA-256 en modo contador y una etiqueta de integridad.
/// **No usar con fondos reales**: la clave vive en memoria del proceso, no en hardware.
pub struct InsecureTestVault {
    key: [u8; 32],
}

impl InsecureTestVault {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    fn keystream_xor(&self, nonce: &[u8; 16], data: &mut [u8]) {
        for (block, chunk) in data.chunks_mut(32).enumerate() {
            let ks = sha256_cat(&[b"ARMAX-TESTVAULT-KS", &self.key, nonce, &(block as u64).to_le_bytes()]);
            for (d, k) in chunk.iter_mut().zip(ks.iter()) {
                *d ^= k;
            }
        }
    }

    fn tag(&self, nonce: &[u8; 16], ct: &[u8]) -> [u8; 16] {
        let t = sha256_cat(&[b"ARMAX-TESTVAULT-TAG", &self.key, nonce, ct]);
        t[..16].try_into().unwrap()
    }
}

impl SecretVault for InsecureTestVault {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
        let mut nonce = [0u8; 16];
        crate::rng::fill_os_random(&mut nonce).map_err(|e| VaultError::Unavailable(e.to_string()))?;
        let mut ct = plaintext.to_vec();
        self.keystream_xor(&nonce, &mut ct);
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        out.extend_from_slice(&self.tag(&nonce, &ct));
        Ok(out)
    }

    fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, VaultError> {
        if sealed.len() < 32 {
            return Err(VaultError::Corrupt);
        }
        let nonce: [u8; 16] = sealed[..16].try_into().unwrap();
        let (ct, tag) = sealed[16..].split_at(sealed.len() - 32);
        if self.tag(&nonce, ct)[..] != tag[..] {
            return Err(VaultError::Corrupt);
        }
        let mut pt = ct.to_vec();
        self.keystream_xor(&nonce, &mut pt);
        Ok(pt)
    }
}

impl Drop for InsecureTestVault {
    fn drop(&mut self) {
        wipe(&mut self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault(n: u8) -> InsecureTestVault {
        InsecureTestVault::new([n; 32])
    }

    #[test]
    fn test_vault_roundtrip_and_tamper_detection() {
        let v = vault(1);
        for len in [0usize, 1, 16, 31, 32, 33, 100] {
            let pt: Vec<u8> = (0..len as u8).collect();
            let sealed = v.seal(&pt).unwrap();
            assert_eq!(v.open(&sealed).unwrap(), pt);
            if len >= 16 {
                assert_ne!(&sealed[16..16 + len], &pt[..], "no debe quedar en claro (len {len})");
            }
            if len > 0 {
                let mut bad = sealed.clone();
                bad[16] ^= 1;
                assert_eq!(v.open(&bad), Err(VaultError::Corrupt));
            }
        }
        // otra bóveda (otra clave) no abre el sellado
        let sealed = v.seal(b"secreto").unwrap();
        assert_eq!(vault(2).open(&sealed), Err(VaultError::Corrupt));
        assert_eq!(v.open(&[0u8; 10]), Err(VaultError::Corrupt));
        // dos sellados del mismo texto difieren (nonce aleatorio)
        assert_ne!(v.seal(b"x").unwrap(), v.seal(b"x").unwrap());
    }

    #[test]
    fn create_unlock_and_restore_give_the_same_keys() {
        let entropy = [0x42u8; 16];
        let (w, mnemonic) = Wallet::create(vault(1), &entropy).unwrap();
        let sealed = w.sealed().to_vec();
        assert!(!sealed.windows(16).any(|win| win == entropy), "la entropía no está en claro");

        let k0 = w.keypair("", 0, 0).unwrap();
        let k1 = w.keypair("", 0, 1).unwrap();
        assert_ne!(k0.public_key(), k1.public_key());
        assert_eq!(w.keypair("", 0, 0).unwrap().public_key(), k0.public_key());

        // la contraseña BIP-39 cambia todas las llaves
        assert_ne!(w.keypair("otra", 0, 0).unwrap().public_key(), k0.public_key());
        // otra cuenta
        assert_ne!(w.keypair("", 1, 0).unwrap().public_key(), k0.public_key());

        // reabrir con el sellado guardado
        let reopened = Wallet::from_sealed(vault(1), sealed);
        assert_eq!(reopened.keypair("", 0, 0).unwrap().public_key(), k0.public_key());

        // restaurar en otro teléfono (otra bóveda, otra clave) con la frase de respaldo
        let restored = Wallet::restore(vault(9), &mnemonic).unwrap();
        assert_eq!(restored.keypair("", 0, 0).unwrap().public_key(), k0.public_key());
        assert_eq!(restored.address("", 0, 1).unwrap(), w.address("", 0, 1).unwrap());
        assert_ne!(restored.sealed(), w.sealed());
    }

    #[test]
    fn wrong_vault_cannot_unlock() {
        let (w, _) = Wallet::create(vault(1), &[7u8; 32]).unwrap();
        let sealed = w.sealed().to_vec();
        let thief = Wallet::from_sealed(vault(2), sealed);
        assert_eq!(thief.keypair("", 0, 0).unwrap_err(), WalletError::Vault(VaultError::Corrupt));
    }

    #[test]
    fn rejects_bad_entropy_length() {
        assert!(matches!(
            Wallet::create(vault(1), &[0u8; 10]),
            Err(WalletError::Mnemonic(Bip39Error::BadEntropyLength(10)))
        ));
    }

    #[test]
    fn full_flow_wallet_to_signed_spend() {
        use crate::tx::{OutPoint, Transaction, TxOut};
        use crate::utxo::{UtxoSet, COINBASE_MATURITY};
        let chain_id = [0x5a; 32];
        let (w, _) = Wallet::create(vault(3), &[0x11; 16]).unwrap();
        let (miner, friend) = (w.keypair("", 0, 0).unwrap(), w.address("", 0, 1).unwrap());
        let miner_addr = address_from_public_key(&miner.public_key());

        let mut set = UtxoSet::new();
        set.apply_coinbase([1; 32], 1, &[(miner_addr, 2_500_000_000)]).unwrap();
        let tx = Transaction::build_signed(
            &[(OutPoint { txid: [1; 32], index: 0 }, &miner)],
            vec![TxOut { address: friend, amount: 1_000_000_000 }, TxOut { address: miner_addr, amount: 1_499_000_000 }],
            &chain_id,
        )
        .unwrap();
        let (fee, _) = set.apply_tx(&tx, 1 + COINBASE_MATURITY, &chain_id).unwrap();
        assert_eq!(fee, 1_000_000);
        assert_eq!(set.balance_of(&friend), 1_000_000_000);
    }
}
