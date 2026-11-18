//! Archivo de cartera **solo para desarrollo**: guarda la clave de sellado junto a la entropía
//! sellada (`InsecureTestVault`), así que quien lea el archivo controla los fondos. En Android
//! la bóveda real es el Keystore (puente UniFFI); este archivo no se usa en producción.

use std::fs;
use std::path::Path;

use armax_chain::Address;
use armax_keys::ed25519::Keypair;
use armax_keys::rng::fill_os_random;
use armax_keys::wallet::{InsecureTestVault, Wallet};

use crate::{hex, unhex};

const HEADER: &str = "armax-wallet-dev-v0";

pub struct WalletFile {
    wallet: Wallet<InsecureTestVault>,
}

impl WalletFile {
    /// Crea una cartera nueva, la guarda en `path` (permisos 0600) y devuelve la frase de respaldo.
    pub fn create(path: &Path) -> Result<(WalletFile, String), String> {
        if path.exists() {
            return Err(format!("{} ya existe: no se sobrescribe", path.display()));
        }
        let mut entropy = [0u8; 16];
        let mut key = [0u8; 32];
        fill_os_random(&mut entropy).map_err(|e| e.to_string())?;
        fill_os_random(&mut key).map_err(|e| e.to_string())?;
        let (wallet, mnemonic) = Wallet::create(InsecureTestVault::new(key), &entropy).map_err(|e| format!("{e:?}"))?;
        let text = format!("{HEADER}\n{}\n{}\n", hex(&key), hex(wallet.sealed()));
        fs::write(path, text).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
        Ok((WalletFile { wallet }, mnemonic.phrase().to_string()))
    }

    pub fn open(path: &Path) -> Result<WalletFile, String> {
        let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut lines = text.lines();
        if lines.next() != Some(HEADER) {
            return Err("no es un archivo de cartera de ARMax".into());
        }
        let key: [u8; 32] = lines
            .next()
            .and_then(unhex)
            .and_then(|b| b.try_into().ok())
            .ok_or("clave dañada")?;
        let sealed = lines.next().and_then(unhex).ok_or("entropía sellada dañada")?;
        Ok(WalletFile { wallet: Wallet::from_sealed(InsecureTestVault::new(key), sealed) })
    }

    /// Dirección de recepción (cuenta 0, índice 0).
    pub fn address(&self) -> Result<Address, String> {
        self.wallet.address("", 0, 0).map_err(|e| format!("{e:?}"))
    }
    pub fn keypair(&self) -> Result<Keypair, String> {
        self.wallet.keypair("", 0, 0).map_err(|e| format!("{e:?}"))
    }
}
