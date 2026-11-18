//! `armax-share`: sharechain (P2Pool) voluntario para mineros pequeños.
//!
//! Con un tope de 40 H/s por dirección y teléfonos de ~5 H/s, minar solo es una lotería de la
//! que casi nadie cobra. El pool reparte cada bloque entre quienes aportaron trabajo reciente, sin
//! custodiar fondos: el coinbase del propio bloque paga a cada minero.
//!
//! * `share`      — el share (bloque candidato con umbral más fácil) y su formato.
//! * `payout`     — regla de reparto determinista (directas + lotería de polvo).
//! * `sharechain` — validación, mejor punta y plantillas.
//! * `store`      — `shares.db`: persistencia de solo añadir, con checksum y compactación.
//!
//! No cambia el consenso de bloques: un bloque con coinbase repartido ya era válido. Quien no
//! participa mina solo, como siempre.

pub mod payout;
pub mod share;
pub mod sharechain;
pub mod store;

pub use payout::payout;
pub use share::{make_extra, Share, ShareMeta, EXTRA_LEN, MAX_SHARE_BYTES, MAX_SHARE_TXS, MAX_SHARE_TX_BYTES, NO_PREV, SHARE_MAGIC};
pub use sharechain::{share_target, share_weight, AddShare, ShareChain, ShareError, ShareParams};
pub use store::{ShareLoadReport, ShareStore, ShareStoreError};
