//! Mensajes del protocolo y su codificación en el cable.
//!
//! ```text
//! trama = "ARMX" | cmd u8 | len u32 LE | sha256(payload)[..4] | payload
//! ```
//! La lectura es estricta: longitud máxima `MAX_PAYLOAD`, listas acotadas, sin bytes sobrantes.
//! Cualquier error de decodificación obliga a cerrar la conexión (la trama ya no es fiable).

use armax_keys::tx::Transaction;
use armax_ledger::FullBlock;
use armax_pow::{BlockHeader, HEADER_LEN, U256};
use armax_share::{Share, MAX_SHARE_BYTES};
use armax_vm::sha256::sha256;

pub type Hash32 = [u8; 32];

pub const MAGIC: [u8; 4] = *b"ARMX";
/// 2: sincronización por cabeceras (`GetHeaders`/`Headers` sustituyen a `GetBlockIds`/`BlockIds`).
/// 3: sharechain (`InvShares`, `GetShareChain`, `Shares`).
/// 4: los shares llevan transacciones.
pub const PROTOCOL_VERSION: u32 = 4;
pub const FRAME_HEADER: usize = 4 + 1 + 4 + 4;
/// Un bloque lleno cabe holgado (≈3 MB en el peor caso).
pub const MAX_PAYLOAD: usize = 4 * 1024 * 1024;
pub const MAX_LOCATOR: usize = 32;
pub const MAX_IDS: usize = 500;
/// Cabeceras por respuesta (124 B cada una).
pub const MAX_HEADERS: usize = 500;
pub const MAX_GETBLOCKS: usize = 16;
pub const MAX_ADDRS: usize = 100;
/// Shares por lote (≈3 KB cada uno sin transacciones; el emisor además limita los bytes).
pub const MAX_SHARES: usize = 64;
/// Ids por anuncio de shares.
pub const MAX_INV_SHARES: usize = 16;

/// Bit de `services`: el nodo acepta conexiones entrantes y sirve bloques.
pub const SERVICE_SERVE: u8 = 1;
/// Bit de `services`: el nodo participa en la sharechain (P2Pool) y quiere sus mensajes.
pub const SERVICE_SHARES: u8 = 2;

#[derive(Debug, PartialEq, Eq)]
pub enum CodecError {
    BadMagic,
    TooLarge(usize),
    BadChecksum,
    UnknownCommand(u8),
    Malformed(&'static str),
}

/// Dirección de un nodo: IPv6 o IPv4 mapeada (`::ffff:a.b.c.d`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NetAddr {
    pub ip: [u8; 16],
    pub port: u16,
    pub services: u8,
    pub last_seen: u64,
}

impl NetAddr {
    pub fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> NetAddr {
        let mut ip = [0u8; 16];
        ip[10] = 0xff;
        ip[11] = 0xff;
        ip[12..].copy_from_slice(&[a, b, c, d]);
        NetAddr { ip, port, services: SERVICE_SERVE, last_seen: 0 }
    }
    pub fn is_unspecified_or_multicast(&self) -> bool {
        let v4 = self.ip[..10] == [0; 10] && self.ip[10] == 0xff && self.ip[11] == 0xff;
        if v4 {
            let o = &self.ip[12..];
            o == [0, 0, 0, 0] || o[0] >= 224
        } else {
            self.ip == [0; 16] || self.ip[0] == 0xff
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    pub protocol: u32,
    pub services: u8,
    pub genesis: Hash32,
    pub tip: Hash32,
    pub tip_height: u64,
    pub tip_work: U256,
    /// Aleatorio por nodo: detecta conexiones a uno mismo.
    pub nonce: u64,
    /// Puerto donde escucha (0 si no acepta conexiones).
    pub listen_port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Version(Version),
    Verack,
    Ping(u64),
    Pong(u64),
    GetAddr,
    Addr(Vec<NetAddr>),
    /// "Dame las cabeceras de tu cadena principal a partir del primero de mi `locator` que conozcas."
    GetHeaders { locator: Vec<Hash32> },
    Headers(Vec<BlockHeader>),
    GetBlocks(Vec<Hash32>),
    Block(Box<FullBlock>),
    NotFound(Vec<Hash32>),
    InvBlocks(Vec<Hash32>),
    InvTxs(Vec<Hash32>),
    GetTxs(Vec<Hash32>),
    Tx(Box<Transaction>),
    /// Shares nuevos que el emisor tiene (solo a pares con `SERVICE_SHARES`).
    InvShares(Vec<Hash32>),
    /// "Dame el share `from` y hasta `max` - 1 ancestros suyos."
    GetShareChain { from: Hash32, max: u16 },
    /// Respuesta: del más antiguo al más reciente; el último es `from`. Vacío = no lo tengo.
    Shares(Vec<Share>),
}

const CMD_VERSION: u8 = 1;
const CMD_VERACK: u8 = 2;
const CMD_PING: u8 = 3;
const CMD_PONG: u8 = 4;
const CMD_GETADDR: u8 = 5;
const CMD_ADDR: u8 = 6;
const CMD_GETHEADERS: u8 = 7;
const CMD_HEADERS: u8 = 8;
const CMD_GETBLOCKS: u8 = 9;
const CMD_BLOCK: u8 = 10;
const CMD_NOTFOUND: u8 = 11;
const CMD_INVBLOCKS: u8 = 12;
const CMD_INVTXS: u8 = 13;
const CMD_GETTXS: u8 = 14;
const CMD_TX: u8 = 15;
const CMD_INVSHARES: u8 = 16;
const CMD_GETSHARECHAIN: u8 = 17;
const CMD_SHARES: u8 = 18;

fn put_ids(b: &mut Vec<u8>, ids: &[Hash32]) {
    b.extend_from_slice(&(ids.len() as u16).to_le_bytes());
    for id in ids {
        b.extend_from_slice(id);
    }
}

impl Message {
    pub fn command(&self) -> u8 {
        match self {
            Message::Version(_) => CMD_VERSION,
            Message::Verack => CMD_VERACK,
            Message::Ping(_) => CMD_PING,
            Message::Pong(_) => CMD_PONG,
            Message::GetAddr => CMD_GETADDR,
            Message::Addr(_) => CMD_ADDR,
            Message::GetHeaders { .. } => CMD_GETHEADERS,
            Message::Headers(_) => CMD_HEADERS,
            Message::GetBlocks(_) => CMD_GETBLOCKS,
            Message::Block(_) => CMD_BLOCK,
            Message::NotFound(_) => CMD_NOTFOUND,
            Message::InvBlocks(_) => CMD_INVBLOCKS,
            Message::InvTxs(_) => CMD_INVTXS,
            Message::GetTxs(_) => CMD_GETTXS,
            Message::Tx(_) => CMD_TX,
            Message::InvShares(_) => CMD_INVSHARES,
            Message::GetShareChain { .. } => CMD_GETSHARECHAIN,
            Message::Shares(_) => CMD_SHARES,
        }
    }

    fn payload(&self) -> Vec<u8> {
        let mut b = Vec::new();
        match self {
            Message::Version(v) => {
                b.extend_from_slice(&v.protocol.to_le_bytes());
                b.push(v.services);
                b.extend_from_slice(&v.genesis);
                b.extend_from_slice(&v.tip);
                b.extend_from_slice(&v.tip_height.to_le_bytes());
                b.extend_from_slice(&v.tip_work.to_be_bytes());
                b.extend_from_slice(&v.nonce.to_le_bytes());
                b.extend_from_slice(&v.listen_port.to_le_bytes());
            }
            Message::Verack | Message::GetAddr => {}
            Message::Ping(n) | Message::Pong(n) => b.extend_from_slice(&n.to_le_bytes()),
            Message::Addr(list) => {
                b.extend_from_slice(&(list.len() as u16).to_le_bytes());
                for a in list {
                    b.extend_from_slice(&a.ip);
                    b.extend_from_slice(&a.port.to_le_bytes());
                    b.push(a.services);
                    b.extend_from_slice(&a.last_seen.to_le_bytes());
                }
            }
            Message::GetHeaders { locator } => put_ids(&mut b, locator),
            Message::Headers(hs) => {
                b.extend_from_slice(&(hs.len() as u16).to_le_bytes());
                for h in hs {
                    b.extend_from_slice(&h.to_bytes());
                }
            }
            Message::GetBlocks(ids)
            | Message::NotFound(ids)
            | Message::InvBlocks(ids)
            | Message::InvTxs(ids)
            | Message::GetTxs(ids) => put_ids(&mut b, ids),
            Message::Block(fb) => b = fb.to_bytes(),
            Message::Tx(t) => b = t.to_bytes(),
            Message::InvShares(ids) => put_ids(&mut b, ids),
            Message::GetShareChain { from, max } => {
                b.extend_from_slice(from);
                b.extend_from_slice(&max.to_le_bytes());
            }
            Message::Shares(list) => {
                b.extend_from_slice(&(list.len() as u16).to_le_bytes());
                for s in list {
                    let sb = s.to_bytes();
                    b.extend_from_slice(&(sb.len() as u32).to_le_bytes());
                    b.extend_from_slice(&sb);
                }
            }
        }
        b
    }

    /// Trama completa lista para enviar.
    pub fn encode(&self) -> Vec<u8> {
        let p = self.payload();
        assert!(p.len() <= MAX_PAYLOAD, "mensaje demasiado grande");
        let mut f = Vec::with_capacity(FRAME_HEADER + p.len());
        f.extend_from_slice(&MAGIC);
        f.push(self.command());
        f.extend_from_slice(&(p.len() as u32).to_le_bytes());
        f.extend_from_slice(&sha256(&p)[..4]);
        f.extend_from_slice(&p);
        f
    }

    fn decode_payload(cmd: u8, p: &[u8]) -> Result<Message, CodecError> {
        let mut r = Rd { d: p, pos: 0 };
        let msg = match cmd {
            CMD_VERSION => Message::Version(Version {
                protocol: r.u32()?,
                services: r.u8()?,
                genesis: r.h32()?,
                tip: r.h32()?,
                tip_height: r.u64()?,
                tip_work: U256::from_be_bytes(&r.h32()?),
                nonce: r.u64()?,
                listen_port: r.u16()?,
            }),
            CMD_VERACK => Message::Verack,
            CMD_GETADDR => Message::GetAddr,
            CMD_PING => Message::Ping(r.u64()?),
            CMD_PONG => Message::Pong(r.u64()?),
            CMD_ADDR => {
                let n = r.u16()? as usize;
                if n > MAX_ADDRS {
                    return Err(CodecError::Malformed("demasiadas direcciones"));
                }
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    let ip: [u8; 16] = r.take(16)?.try_into().unwrap();
                    v.push(NetAddr { ip, port: r.u16()?, services: r.u8()?, last_seen: r.u64()? });
                }
                Message::Addr(v)
            }
            CMD_GETHEADERS => Message::GetHeaders { locator: r.ids(MAX_LOCATOR)? },
            CMD_HEADERS => {
                let n = r.u16()? as usize;
                if n > MAX_HEADERS {
                    return Err(CodecError::Malformed("demasiadas cabeceras"));
                }
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    v.push(BlockHeader::from_bytes(r.take(HEADER_LEN)?).map_err(|_| CodecError::Malformed("cabecera inválida"))?);
                }
                Message::Headers(v)
            }
            CMD_GETBLOCKS => Message::GetBlocks(r.ids(MAX_GETBLOCKS)?),
            CMD_NOTFOUND => Message::NotFound(r.ids(MAX_GETBLOCKS.max(MAX_IDS))?),
            CMD_INVBLOCKS => Message::InvBlocks(r.ids(MAX_IDS)?),
            CMD_INVTXS => Message::InvTxs(r.ids(MAX_IDS)?),
            CMD_GETTXS => Message::GetTxs(r.ids(MAX_IDS)?),
            CMD_BLOCK => return FullBlock::from_bytes(p).map(|b| Message::Block(Box::new(b))).map_err(CodecError::Malformed),
            CMD_TX => {
                return Transaction::from_bytes(p)
                    .map(|t| Message::Tx(Box::new(t)))
                    .map_err(|_| CodecError::Malformed("transacción inválida"))
            }
            CMD_INVSHARES => Message::InvShares(r.ids(MAX_INV_SHARES)?),
            CMD_GETSHARECHAIN => Message::GetShareChain { from: r.h32()?, max: r.u16()? },
            CMD_SHARES => {
                let n = r.u16()? as usize;
                if n > MAX_SHARES {
                    return Err(CodecError::Malformed("demasiados shares"));
                }
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    let len = r.u32()? as usize;
                    if len > MAX_SHARE_BYTES {
                        return Err(CodecError::Malformed("share demasiado grande"));
                    }
                    v.push(Share::from_bytes(r.take(len)?).map_err(CodecError::Malformed)?);
                }
                Message::Shares(v)
            }
            other => return Err(CodecError::UnknownCommand(other)),
        };
        if r.pos != p.len() {
            return Err(CodecError::Malformed("bytes sobrantes"));
        }
        Ok(msg)
    }
}

struct Rd<'a> {
    d: &'a [u8],
    pos: usize,
}
impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        let end = self.pos.checked_add(n).ok_or(CodecError::Malformed("desbordamiento"))?;
        let s = self.d.get(self.pos..end).ok_or(CodecError::Malformed("datos cortos"))?;
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, CodecError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, CodecError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn h32(&mut self) -> Result<Hash32, CodecError> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    fn ids(&mut self, max: usize) -> Result<Vec<Hash32>, CodecError> {
        let n = self.u16()? as usize;
        if n > max {
            return Err(CodecError::Malformed("demasiados ids"));
        }
        (0..n).map(|_| self.h32()).collect()
    }
}

/// Decodificador incremental: se le entregan los bytes tal como llegan del socket.
#[derive(Default)]
pub struct Decoder {
    buf: Vec<u8>,
}

impl Decoder {
    pub fn new() -> Decoder {
        Decoder::default()
    }
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }
    /// Siguiente mensaje completo, `Ok(None)` si faltan bytes. Un `Err` es definitivo.
    pub fn next(&mut self) -> Result<Option<Message>, CodecError> {
        if self.buf.len() < FRAME_HEADER {
            if !self.buf.is_empty() && self.buf[..self.buf.len().min(4)] != MAGIC[..self.buf.len().min(4)] {
                return Err(CodecError::BadMagic);
            }
            return Ok(None);
        }
        if self.buf[..4] != MAGIC {
            return Err(CodecError::BadMagic);
        }
        let cmd = self.buf[4];
        let len = u32::from_le_bytes(self.buf[5..9].try_into().unwrap()) as usize;
        if len > MAX_PAYLOAD {
            return Err(CodecError::TooLarge(len));
        }
        if self.buf.len() < FRAME_HEADER + len {
            return Ok(None);
        }
        let payload = &self.buf[FRAME_HEADER..FRAME_HEADER + len];
        if self.buf[9..13] != sha256(payload)[..4] {
            return Err(CodecError::BadChecksum);
        }
        let msg = Message::decode_payload(cmd, payload)?;
        self.buf.drain(..FRAME_HEADER + len);
        Ok(Some(msg))
    }
}

/// Atajo para pruebas y para quien lee una trama completa.
pub fn decode_one(frame: &[u8]) -> Result<Message, CodecError> {
    let mut d = Decoder::new();
    d.push(frame);
    match d.next()? {
        Some(m) if d.buffered() == 0 => Ok(m),
        Some(_) => Err(CodecError::Malformed("bytes sobrantes")),
        None => Err(CodecError::Malformed("trama incompleta")),
    }
}

