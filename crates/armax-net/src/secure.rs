//! Canal cifrado entre nodos: apretón de manos X25519 efímero + registros ChaCha20-Poly1305.
//!
//! ```text
//! iniciador → "ARMXSEC1" | e_i(32)          respondedor → e_r(32)
//! shared = X25519(e_priv, e_peer)           (se rechaza si es todo ceros)
//! h      = SHA256("ARMX-NN-1" | e_i | e_r)
//! prk    = HKDF-Extract(salt = h, ikm = shared)
//!
//! Variante con identidad ("ARMXSEC2", patrón NK): el iniciador conoce de antemano la clave
//! estática `s_r` de un nodo (la "fija") y mezcla además `X25519(e_i, s_r)`; solo quien tenga el
//! secreto de `s_r` deriva las mismas claves, así que un intermediario no puede hacerse pasar por
//! ese nodo (la confirmación de claves falla). `h` incluye `s_r` y el ikm es `ee | es`.
//! k_i2r | k_r2i = HKDF-Expand(prk, "ARMX-keys", 64)
//! cada lado envía un registro cifrado con h (confirmación de claves)
//! registro = len u32 BE | ChaCha20-Poly1305(clave del sentido, nonce = contador u64, aad = len)
//! ```
//!
//! # Qué da y qué no da
//! * Da confidencialidad e integridad frente a quien solo observa o altera tráfico en la red
//!   (Wi-Fi público, operador), claves nuevas por conexión (secreto hacia adelante), y rechazo de
//!   repetición/reordenación (el contador de cada sentido forma parte del nonce).
//! * Sin clave fijada **no autentica al par**: en una red sin permisos nadie tiene identidad, y
//!   un atacante activo en medio de una conexión normal no se detecta. Con la clave de un nodo
//!   fijada (`--pin`), sí: ese nodo queda autenticado y un impostor no puede conectarse como él.
//!   Una conexión con clave fijada nunca baja a la variante sin identidad.
//! * No hay vuelta atrás a texto claro: un par que no habla este protocolo se desconecta.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use armax_keys::aead;
use armax_keys::ed25519::wipe;
use armax_keys::kdf::{hkdf_expand, hkdf_extract};
use armax_keys::rng::fill_os_random;
use armax_keys::x25519::{is_all_zero, public_key, x25519};
use armax_vm::sha256::sha256_cat;

pub const MAGIC: &[u8; 8] = b"ARMXSEC1";
pub const MAGIC_PINNED: &[u8; 8] = b"ARMXSEC2";

/// Identidad opcional de un extremo del apretón de manos.
#[derive(Clone, Copy, Default)]
pub struct Auth {
    /// Iniciador: clave pública estática que debe tener el nodo al que marca.
    pub pin: Option<[u8; 32]>,
    /// Respondedor: secreto estático del nodo (para aceptar a quienes lo fijan).
    pub identity: Option<[u8; 32]>,
}
/// Texto claro máximo por registro. Una trama grande se parte en varios.
pub const MAX_RECORD_PLAIN: usize = 16 * 1024;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

fn bad(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn nonce_of(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    n
}

/// Lado de escritura del canal.
pub struct SendState {
    key: [u8; 32],
    ctr: u64,
}

impl SendState {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key, ctr: 0 }
    }

    /// Cifra `data` como uno o más registros listos para escribir en el socket.
    pub fn seal(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() + (data.len() / MAX_RECORD_PLAIN + 1) * 20);
        for chunk in data.chunks(MAX_RECORD_PLAIN) {
            let len = ((chunk.len() + aead::TAG_LEN) as u32).to_be_bytes();
            let ct = aead::seal(&self.key, &nonce_of(self.ctr), &len, chunk);
            self.ctr = self.ctr.checked_add(1).expect("contador agotado");
            out.extend_from_slice(&len);
            out.extend_from_slice(&ct);
        }
        out
    }
}

impl Drop for SendState {
    fn drop(&mut self) {
        wipe(&mut self.key);
    }
}

/// Lado de lectura del canal.
pub struct RecvState {
    key: [u8; 32],
    ctr: u64,
}

impl RecvState {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key, ctr: 0 }
    }

    /// Lee y descifra un registro. Error si el tamaño es absurdo o la etiqueta no cuadra.
    pub fn read_record<R: Read>(&mut self, r: &mut R) -> io::Result<Vec<u8>> {
        let mut len = [0u8; 4];
        r.read_exact(&mut len)?;
        let n = u32::from_be_bytes(len) as usize;
        if n < aead::TAG_LEN || n > MAX_RECORD_PLAIN + aead::TAG_LEN {
            return Err(bad("tamaño de registro inválido"));
        }
        let mut ct = vec![0u8; n];
        r.read_exact(&mut ct)?;
        let pt = aead::open(&self.key, &nonce_of(self.ctr), &len, &ct).ok_or_else(|| bad("registro corrupto"))?;
        self.ctr = self.ctr.checked_add(1).ok_or_else(|| bad("contador agotado"))?;
        Ok(pt)
    }
}

impl Drop for RecvState {
    fn drop(&mut self) {
        wipe(&mut self.key);
    }
}

/// Apretón de manos sobre un socket recién conectado. Deja el socket sin tiempos de espera.
pub fn handshake(stream: &mut TcpStream, initiator: bool) -> io::Result<(SendState, RecvState)> {
    handshake_auth(stream, initiator, &Auth::default())
}

pub fn handshake_auth(stream: &mut TcpStream, initiator: bool, auth: &Auth) -> io::Result<(SendState, RecvState)> {
    handshake_with_timeout(stream, initiator, auth, HANDSHAKE_TIMEOUT)
}

pub fn handshake_with_timeout(
    stream: &mut TcpStream,
    initiator: bool,
    auth: &Auth,
    timeout: Duration,
) -> io::Result<(SendState, RecvState)> {
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let _ = stream.set_nodelay(true);

    let mut secret = [0u8; 32];
    fill_os_random(&mut secret)?;
    let mine = public_key(&secret);

    // `es`: DH entre la efímera del iniciador y la estática del respondedor (solo variante fijada)
    let (e_i, e_r, theirs, mut es, static_pub);
    if initiator {
        let mut hello = [0u8; 40];
        hello[..8].copy_from_slice(if auth.pin.is_some() { MAGIC_PINNED } else { MAGIC });
        hello[8..].copy_from_slice(&mine);
        stream.write_all(&hello)?;
        let mut r = [0u8; 32];
        stream.read_exact(&mut r)?;
        (e_i, e_r, theirs) = (mine, r, r);
        static_pub = auth.pin;
        es = auth.pin.map(|rs| x25519(&secret, &rs));
    } else {
        let mut hello = [0u8; 40];
        stream.read_exact(&mut hello)?;
        let pinned = &hello[..8] == MAGIC_PINNED;
        if &hello[..8] != MAGIC && !pinned {
            wipe(&mut secret);
            return Err(bad("el par no habla el protocolo cifrado de ARMax"));
        }
        let i: [u8; 32] = hello[8..].try_into().unwrap();
        (e_i, e_r, theirs) = (i, mine, i);
        if pinned {
            let Some(id) = auth.identity else {
                wipe(&mut secret);
                return Err(bad("el par exige una identidad que este nodo no tiene"));
            };
            static_pub = Some(public_key(&id));
            es = Some(x25519(&id, &i));
        } else {
            static_pub = None;
            es = None;
        }
        stream.write_all(&mine)?;
    }

    let mut shared = x25519(&secret, &theirs);
    wipe(&mut secret);
    if is_all_zero(&shared) || es.map_or(false, |x| is_all_zero(&x)) {
        return Err(bad("clave efímera inválida (punto de orden bajo)"));
    }
    let transcript = match &static_pub {
        None => sha256_cat(&[b"ARMX-NN-1", &e_i, &e_r]),
        Some(rs) => sha256_cat(&[b"ARMX-NK-1", &e_i, &e_r, rs]),
    };
    let mut ikm = shared.to_vec();
    if let Some(x) = es.as_mut() {
        ikm.extend_from_slice(x);
        wipe(x);
    }
    let mut prk = hkdf_extract(&transcript, &ikm);
    wipe(&mut ikm);
    wipe(&mut shared);
    let mut okm = [0u8; 64];
    hkdf_expand(&prk, b"ARMX-keys", &mut okm);
    wipe(&mut prk);
    let (k_i2r, k_r2i): ([u8; 32], [u8; 32]) = (okm[..32].try_into().unwrap(), okm[32..].try_into().unwrap());
    wipe(&mut okm);
    let (mut send, mut recv) = if initiator {
        (SendState::new(k_i2r), RecvState::new(k_r2i))
    } else {
        (SendState::new(k_r2i), RecvState::new(k_i2r))
    };

    // confirmación de claves: cada lado prueba que derivó las mismas
    stream.write_all(&send.seal(&transcript))?;
    let theirs_confirm = recv.read_record(stream)?;
    if theirs_confirm != transcript {
        return Err(bad("confirmación de claves incorrecta"));
    }
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;
    Ok((send, recv))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::TcpListener;
    use std::thread;

    fn pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let c = TcpStream::connect(addr).unwrap();
        let (s, _) = l.accept().unwrap();
        (c, s)
    }

    #[test]
    fn handshake_then_bulk_data_both_ways() {
        let (mut c, mut s) = pair();
        let srv = thread::spawn(move || {
            let (mut tx, mut rx) = handshake(&mut s, false).unwrap();
            let got = rx.read_record(&mut s).unwrap();
            assert_eq!(got, b"hola");
            // 100 000 bytes → varios registros
            let big: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
            s.write_all(&tx.seal(&big)).unwrap();
            big
        });
        let (mut tx, mut rx) = handshake(&mut c, true).unwrap();
        c.write_all(&tx.seal(b"hola")).unwrap();
        let mut got = Vec::new();
        while got.len() < 100_000 {
            got.extend(rx.read_record(&mut c).unwrap());
        }
        assert_eq!(got, srv.join().unwrap());
    }

    #[test]
    fn a_plaintext_peer_is_refused() {
        let (mut c, mut s) = pair();
        let srv = thread::spawn(move || handshake(&mut s, false).map(|_| ()));
        c.write_all(&[0x41; 40]).unwrap(); // basura del tamaño del saludo
        assert!(srv.join().unwrap().is_err());
    }

    #[test]
    fn a_silent_peer_times_out() {
        let (mut c, _s) = pair();
        let t = std::time::Instant::now();
        let r = handshake_with_timeout(&mut c, true, &Auth::default(), Duration::from_millis(300));
        assert!(r.is_err());
        assert!(t.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn low_order_ephemeral_key_is_refused() {
        let (mut c, mut s) = pair();
        let srv = thread::spawn(move || handshake(&mut s, false).map(|_| ()));
        let mut hello = [0u8; 40];
        hello[..8].copy_from_slice(MAGIC); // e_i = 0
        c.write_all(&hello).unwrap();
        assert!(srv.join().unwrap().is_err());
    }

    fn run_pair(client: Auth, server: Auth) -> (io::Result<()>, io::Result<()>) {
        let (mut c, mut s) = pair();
        let srv = thread::spawn(move || {
            let r = handshake_auth(&mut s, false, &server);
            r.map(|(mut tx, mut rx)| {
                let got = rx.read_record(&mut s).unwrap();
                s.write_all(&tx.seal(&got)).unwrap();
            })
        });
        let cr = handshake_auth(&mut c, true, &client).and_then(|(mut tx, mut rx)| {
            c.write_all(&tx.seal(b"eco"))?;
            let back = rx.read_record(&mut c)?;
            assert_eq!(back, b"eco");
            Ok(())
        });
        // si el cliente aborta, el servidor puede quedarse esperando: se cierra para liberarlo
        drop(c);
        (cr, srv.join().unwrap())
    }

    #[test]
    fn pinned_key_authenticates_the_server() {
        let secret = [0x42u8; 32];
        let public = public_key(&secret);
        // clave correcta: funciona en ambos sentidos
        let (c, s) = run_pair(Auth { pin: Some(public), identity: None }, Auth { pin: None, identity: Some(secret) });
        assert!(c.is_ok() && s.is_ok(), "{c:?} {s:?}");
        // sin fijar, un servidor con identidad sigue aceptando (variante abierta)
        let (c, s) = run_pair(Auth::default(), Auth { pin: None, identity: Some(secret) });
        assert!(c.is_ok() && s.is_ok());
        // un impostor con otra clave no pasa la confirmación
        let (c, _s) = run_pair(Auth { pin: Some(public), identity: None }, Auth { pin: None, identity: Some([0x43u8; 32]) });
        assert!(c.is_err(), "el iniciador aceptó a un impostor");
        // un servidor sin identidad rechaza a quien exige una, y no baja a modo abierto
        let (c, s) = run_pair(Auth { pin: Some(public), identity: None }, Auth::default());
        assert!(c.is_err() && s.is_err());
        // un punto de orden bajo como clave fijada se rechaza
        let (c, _s) = run_pair(Auth { pin: Some([0u8; 32]), identity: None }, Auth { pin: None, identity: Some(secret) });
        assert!(c.is_err());
    }

    #[test]
    fn records_reject_tampering_replay_and_reordering() {
        let key = [9u8; 32];
        let mut tx = SendState::new(key);
        let a = tx.seal(b"primero");
        let b = tx.seal(b"segundo");
        // en orden
        let mut rx = RecvState::new(key);
        let mut stream = Cursor::new([a.clone(), b.clone()].concat());
        assert_eq!(rx.read_record(&mut stream).unwrap(), b"primero");
        assert_eq!(rx.read_record(&mut stream).unwrap(), b"segundo");
        // reordenados
        let mut rx = RecvState::new(key);
        assert!(rx.read_record(&mut Cursor::new([b.clone(), a.clone()].concat())).is_err());
        // repetidos
        let mut rx = RecvState::new(key);
        let mut st = Cursor::new([a.clone(), a.clone()].concat());
        assert!(rx.read_record(&mut st).is_ok());
        assert!(rx.read_record(&mut st).is_err());
        // un bit cambiado en cualquier posición (longitud incluida)
        for i in 0..a.len() {
            let mut bad = a.clone();
            bad[i] ^= 1;
            let mut rx = RecvState::new(key);
            assert!(rx.read_record(&mut Cursor::new(bad)).is_err(), "byte {i}");
        }
        // longitud gigante: no reserva memoria
        let mut rx = RecvState::new(key);
        assert!(rx.read_record(&mut Cursor::new(vec![0xff, 0xff, 0xff, 0xff, 0])).is_err());
        // trama vacía no genera registros
        assert!(SendState::new(key).seal(&[]).is_empty());
    }
}
