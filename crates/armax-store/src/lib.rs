//! `armax-store`: guarda los bloques en un archivo de solo añadir y reconstruye el libro mayor
//! al arrancar.
//!
//! # Qué se guarda y qué no
//! Solo bloques completos (cabecera + coinbase + transacciones), en el orden en que el libro
//! mayor los aceptó. **El estado (UTXO, punta, trabajo) no se guarda**: se reconstruye
//! re-ejecutando los bloques. Un archivo dañado no puede, por tanto, producir saldos falsos:
//! lo peor que puede hacer es perder bloques, que se vuelven a descargar de la red.
//!
//! # Formato
//! ```text
//! archivo  = "ARMAXDB1" | genesis_id (32) | registro*
//! registro = len u32 LE | payload (FullBlock::to_bytes) | sha256(payload)[..8]
//! ```
//! El `genesis_id` evita abrir por error el archivo de otra red.
//!
//! # Recuperación
//! Al abrir se lee hasta el primer registro incompleto, con checksum erróneo, que no
//! decodifique o que el libro mayor rechace; el archivo se **trunca** ahí y se informa en
//! `OpenReport`. Esto cubre el caso normal (corte de energía o app cerrada a mitad de una
//! escritura: cola incompleta). Cada bloque se sincroniza con `sync_data` antes de devolver.
//!
//! # Verificación del PoW al reconstruir
//! `open` recibe el `PowCheck`: con `VmPow` se re-verifica todo (≈0.2 s por bloque en un
//! teléfono); con `SkipPow` el arranque es rápido y confía en el checksum, que detecta
//! corrupción accidental pero no manipulación deliberada del archivo.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use armax_chain::{AddOutcome, PowCheck};
use armax_ledger::{FullBlock, Ledger, LedgerError};
use armax_vm::sha256::sha256;

pub const MAGIC: &[u8; 8] = b"ARMAXDB1";
const HEAD_LEN: u64 = 8 + 32;
/// Tope de un registro: protege contra longitudes absurdas en un archivo dañado.
pub const MAX_RECORD: usize = 4 * 1024 * 1024;

#[derive(Debug)]
pub enum StoreError {
    Io(io::Error),
    /// El archivo no empieza con la cabecera esperada.
    BadHeader,
    /// El archivo pertenece a otra cadena.
    WrongNetwork,
    Ledger(LedgerError),
}
impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        StoreError::Io(e)
    }
}
impl From<LedgerError> for StoreError {
    fn from(e: LedgerError) -> Self {
        StoreError::Ledger(e)
    }
}
impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for StoreError {}

/// Resultado de abrir: cuánto se cargó y si hubo que cortar una cola dañada.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct OpenReport {
    pub blocks_loaded: usize,
    pub truncated_bytes: u64,
    /// Motivo del truncado, si lo hubo.
    pub reason: Option<String>,
}

pub struct Store {
    file: File,
}

fn checksum(payload: &[u8]) -> [u8; 8] {
    sha256(payload)[..8].try_into().unwrap()
}

impl Store {
    /// Abre (o crea) el archivo y reconstruye `ledger`, que debe ser recién creado (solo génesis).
    pub fn open(
        path: &Path,
        ledger: &mut Ledger,
        now: u64,
        pow: &mut dyn PowCheck,
    ) -> Result<(Store, OpenReport), StoreError> {
        let genesis = ledger.chain().genesis_id();
        let mut file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;
        let size = file.metadata()?.len();
        if size == 0 {
            file.write_all(MAGIC)?;
            file.write_all(&genesis)?;
            file.sync_data()?;
            return Ok((Store { file }, OpenReport::default()));
        }
        if size < HEAD_LEN {
            return Err(StoreError::BadHeader);
        }
        let mut head = [0u8; HEAD_LEN as usize];
        file.read_exact(&mut head)?;
        if &head[..8] != MAGIC {
            return Err(StoreError::BadHeader);
        }
        if head[8..] != genesis {
            return Err(StoreError::WrongNetwork);
        }

        let mut data = Vec::with_capacity((size - HEAD_LEN) as usize);
        file.read_to_end(&mut data)?;
        let mut pos = 0usize;
        let mut report = OpenReport::default();
        let mut bad: Option<String> = None;
        while pos < data.len() {
            let rest = &data[pos..];
            if rest.len() < 4 {
                bad = Some("registro incompleto".into());
                break;
            }
            let len = u32::from_le_bytes(rest[..4].try_into().unwrap()) as usize;
            if len == 0 || len > MAX_RECORD {
                bad = Some(format!("longitud de registro absurda ({len})"));
                break;
            }
            if rest.len() < 4 + len + 8 {
                bad = Some("registro incompleto".into());
                break;
            }
            let payload = &rest[4..4 + len];
            if rest[4 + len..4 + len + 8] != checksum(payload) {
                bad = Some("checksum incorrecto".into());
                break;
            }
            let fb = match FullBlock::from_bytes(payload) {
                Ok(fb) => fb,
                Err(e) => {
                    bad = Some(format!("no decodifica: {e}"));
                    break;
                }
            };
            match ledger.add_block(fb, now, pow) {
                Ok(_) => {}
                Err(e) => {
                    bad = Some(format!("el libro mayor lo rechaza: {e}"));
                    break;
                }
            }
            report.blocks_loaded += 1;
            pos += 4 + len + 8;
        }
        if let Some(reason) = bad {
            report.truncated_bytes = (data.len() - pos) as u64;
            report.reason = Some(reason);
            file.set_len(HEAD_LEN + pos as u64)?;
            file.sync_data()?;
        }
        file.seek(SeekFrom::End(0))?;
        Ok((Store { file }, report))
    }

    /// Valida el bloque en el libro mayor y, si lo acepta como nuevo, lo añade al archivo
    /// (con `sync_data`). Un bloque rechazado o ya conocido no se escribe.
    pub fn add_block(
        &mut self,
        ledger: &mut Ledger,
        fb: FullBlock,
        now: u64,
        pow: &mut dyn PowCheck,
    ) -> Result<AddOutcome, StoreError> {
        let payload = fb.to_bytes();
        let outcome = ledger.add_block(fb, now, pow)?;
        if outcome != AddOutcome::AlreadyKnown {
            let mut rec = Vec::with_capacity(payload.len() + 12);
            rec.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            rec.extend_from_slice(&payload);
            rec.extend_from_slice(&checksum(&payload));
            self.file.write_all(&rec)?;
            self.file.sync_data()?;
        }
        Ok(outcome)
    }
}
