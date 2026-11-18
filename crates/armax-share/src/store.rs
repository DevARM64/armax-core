//! Persistencia de la sharechain: un archivo de solo añadir, `shares.db`.
//!
//! # Qué se guarda y por qué es seguro
//! Solo los shares, tal cual se aceptaron. **Nada derivado** (pesos, alturas, punta): al abrir se
//! re-ejecutan por `ShareChain::add`, con toda su validación (enlaces, reparto, PoW). Un archivo
//! dañado o manipulado no puede producir una sharechain falsa; lo peor es perder shares, que los
//! pares vuelven a dar. Con `pow` = verificador de confianza (`--trust-store`) se omite solo la
//! VM, como en `blocks.db`.
//!
//! # Formato
//! ```text
//! archivo  = "ARMAXSH2" | genesis_id (32) | registro*
//! registro = len u32 LE | Share::to_bytes | sha256(payload)[..8]
//! ```
//! Se escribe sin `fsync` por share (la sharechain es recuperable de la red y un share por segundo
//! sincronizado cansaría la memoria flash del teléfono): una caída del proceso no pierde nada
//! porque el sistema ya tiene los bytes; un corte de energía puede perder la cola, que se recorta.
//!
//! # Compactación
//! La sharechain en memoria poda su historia (~2 ventanas); el archivo solo crece. Al abrir, y
//! durante la marcha cuando tiene muchos más registros que shares vivos, se reescribe con los
//! shares actuales (en orden: cada padre antes que sus hijos) en un archivo temporal que luego
//! sustituye al original con `rename`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use armax_chain::{Chain, SharePowCheck};
use armax_pow::Hash32;
use armax_vm::sha256::sha256;

use crate::share::{Share, MAX_SHARE_BYTES};
use crate::sharechain::ShareChain;

pub const MAGIC: &[u8; 8] = b"ARMAXSH2";
/// Formato anterior (shares sin transacciones): se descarta, la sharechain se recupera de la red.
const MAGIC_V1: &[u8; 8] = b"ARMAXSH1";
const HEAD_LEN: u64 = 8 + 32;

#[derive(Debug)]
pub enum ShareStoreError {
    Io(io::Error),
    /// El archivo no empieza con la cabecera esperada.
    BadHeader,
    /// El archivo pertenece a otra cadena.
    WrongNetwork,
}
impl From<io::Error> for ShareStoreError {
    fn from(e: io::Error) -> Self {
        ShareStoreError::Io(e)
    }
}
impl core::fmt::Display for ShareStoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ShareStoreError::Io(e) => write!(f, "{e}"),
            ShareStoreError::BadHeader => write!(f, "no es un archivo de shares de ARMax"),
            ShareStoreError::WrongNetwork => write!(f, "pertenece a otra red"),
        }
    }
}
impl std::error::Error for ShareStoreError {}

/// Resultado de abrir.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ShareLoadReport {
    /// Shares leídos del archivo y aceptados por la sharechain.
    pub loaded: usize,
    /// Leídos pero rechazados (p. ej. su bloque padre ya no está en `blocks.db`).
    pub skipped: usize,
    pub truncated_bytes: u64,
    pub reason: Option<String>,
    /// Se reescribió el archivo para quitar lo podado.
    pub compacted: bool,
}

pub struct ShareStore {
    file: File,
    path: PathBuf,
    genesis: Hash32,
    /// Registros que hay ahora en el archivo.
    records: usize,
}

fn checksum(payload: &[u8]) -> [u8; 8] {
    sha256(payload)[..8].try_into().unwrap()
}

fn record(payload: &[u8]) -> Vec<u8> {
    let mut rec = Vec::with_capacity(payload.len() + 12);
    rec.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    rec.extend_from_slice(payload);
    rec.extend_from_slice(&checksum(payload));
    rec
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

impl ShareStore {
    /// Abre (o crea) el archivo y rellena `sc`, que debe estar vacía, con lo que contiene.
    /// `chain` debe tener ya todos los bloques cargados (los shares cuelgan de ellos).
    pub fn open(
        path: &Path,
        chain: &Chain,
        sc: &mut ShareChain,
        now: u64,
        pow: &mut dyn SharePowCheck,
    ) -> Result<(ShareStore, ShareLoadReport), ShareStoreError> {
        let genesis = chain.genesis_id();
        // un archivo del formato anterior es solo una copia de lo que los pares dan: se empieza de cero
        if let Ok(mut f) = File::open(path) {
            let mut m = [0u8; 8];
            if f.read_exact(&mut m).is_ok() && &m == MAGIC_V1 {
                drop(f);
                fs::remove_file(path)?;
            }
        }
        let mut file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;
        let size = file.metadata()?.len();
        let mut report = ShareLoadReport::default();
        if size == 0 {
            file.write_all(MAGIC)?;
            file.write_all(&genesis)?;
            file.sync_data()?;
            return Ok((ShareStore { file, path: path.to_path_buf(), genesis, records: 0 }, report));
        }
        if size < HEAD_LEN {
            return Err(ShareStoreError::BadHeader);
        }
        let mut head = [0u8; HEAD_LEN as usize];
        file.read_exact(&mut head)?;
        if &head[..8] != MAGIC {
            return Err(ShareStoreError::BadHeader);
        }
        if head[8..] != genesis {
            return Err(ShareStoreError::WrongNetwork);
        }
        let mut data = Vec::with_capacity((size - HEAD_LEN) as usize);
        file.read_to_end(&mut data)?;

        let mut pos = 0usize;
        let mut records = 0usize;
        let mut bad: Option<String> = None;
        while pos < data.len() {
            let rest = &data[pos..];
            if rest.len() < 4 {
                bad = Some("registro incompleto".into());
                break;
            }
            let len = u32::from_le_bytes(rest[..4].try_into().unwrap()) as usize;
            if len == 0 || len > MAX_SHARE_BYTES {
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
            let share = match Share::from_bytes(payload) {
                Ok(s) => s,
                Err(e) => {
                    bad = Some(format!("no decodifica: {e}"));
                    break;
                }
            };
            // `add_base`: si la sharechain guardada empezaba en un horizonte (el par ya había
            // podado su raíz) o si la poda quitó el principio, el primer share no tiene anterior
            records += 1;
            match sc.add_base(share, chain, now, pow) {
                Ok(_) => report.loaded += 1,
                Err(_) => report.skipped += 1,
            }
            pos += 4 + len + 8;
        }
        if let Some(reason) = bad {
            report.truncated_bytes = (data.len() - pos) as u64;
            report.reason = Some(reason);
            file.set_len(HEAD_LEN + pos as u64)?;
            file.sync_data()?;
        }
        file.seek(SeekFrom::End(0))?;
        let mut store = ShareStore { file, path: path.to_path_buf(), genesis, records };
        if store.needs_compaction(sc.len()) {
            store.compact(sc)?;
            report.compacted = true;
        }
        Ok((store, report))
    }

    /// Añade un share aceptado. Sin `fsync` (ver el encabezado del módulo).
    pub fn append(&mut self, share: &Share) -> io::Result<()> {
        self.file.write_all(&record(&share.to_bytes()))?;
        self.records += 1;
        Ok(())
    }

    pub fn records(&self) -> usize {
        self.records
    }

    /// ¿Tiene el archivo mucho más de lo que la sharechain conserva?
    pub fn needs_compaction(&self, live: usize) -> bool {
        self.records > live.saturating_mul(2) + 256
    }

    /// Reescribe el archivo con los shares vivos de `sc`.
    pub fn compact(&mut self, sc: &ShareChain) -> io::Result<()> {
        let tmp = tmp_path(&self.path);
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&self.genesis);
        let mut n = 0usize;
        for s in sc.shares_in_order() {
            buf.extend_from_slice(&record(&s.to_bytes()));
            n += 1;
        }
        {
            let mut f = File::create(&tmp)?;
            f.write_all(&buf)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        let mut file = OpenOptions::new().read(true).write(true).open(&self.path)?;
        file.seek(SeekFrom::End(0))?;
        self.file = file;
        self.records = n;
        Ok(())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.file.sync_data()
    }
}
