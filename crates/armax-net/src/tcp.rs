//! Transporte TCP con `std::net` e hilos.
//!
//! Un hilo "núcleo" es el único dueño del `Node`. Cada conexión tiene un hilo lector (decodifica
//! tramas y las entrega al núcleo) y uno escritor (con cola acotada: un par lento no puede
//! acumular memoria; si la cola se llena se le desconecta). El hilo de escucha solo acepta
//! sockets. Los hilos de marcado hacen `connect_timeout` fuera del núcleo.

use std::collections::HashMap;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use armax_keys::tx::Transaction;
use armax_ledger::{FullBlock, LedgerError};
use armax_mempool::{AddResult, MempoolError};

use crate::codec::{Decoder, NetAddr, SERVICE_SERVE};
use crate::node::{Action, Event, Node, PeerId};
use crate::secure::{self, Auth, RecvState, SendState};
use armax_chain::AddOutcome;
use armax_share::{AddShare, Share, ShareError};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_QUEUE: usize = 64;
/// Conexiones entrantes en pleno apretón de manos a la vez (cada una ocupa un hilo hasta 5 s).
const MAX_HANDSHAKES: usize = 64;

/// Conexión ya cifrada, lista para registrarse en el núcleo.
struct Secure {
    stream: TcpStream,
    send: SendState,
    recv: RecvState,
}

pub fn to_netaddr(sa: SocketAddr) -> NetAddr {
    let ip = match sa.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    };
    NetAddr { ip, port: sa.port(), services: SERVICE_SERVE, last_seen: 0 }
}

pub fn to_socketaddr(a: &NetAddr) -> SocketAddr {
    let v6 = Ipv6Addr::from(a.ip);
    let ip = match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    };
    SocketAddr::new(ip, a.port)
}

enum Core {
    Incoming(Secure, SocketAddr),
    Outgoing(Secure, NetAddr),
    DialFailed(NetAddr),
    Frame(PeerId, crate::codec::Message),
    Closed(PeerId),
    Query(Box<dyn FnOnce(&mut Node) + Send>),
    SubmitTx(Transaction, Sender<Result<AddResult, MempoolError>>),
    SubmitBlock(Box<FullBlock>, Sender<Result<AddOutcome, LedgerError>>),
    SubmitShare(Box<Share>, Sender<Result<AddShare, ShareError>>),
    Stop,
}

pub struct NodeHandle {
    tx: Sender<Core>,
    join: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    pub local_addr: Option<SocketAddr>,
}

impl NodeHandle {
    /// Ejecuta `f` con el nodo (solo lectura de estado; para enviar usa `submit_*`).
    pub fn query<R: Send + 'static>(&self, f: impl FnOnce(&mut Node) -> R + Send + 'static) -> Option<R> {
        let (rtx, rrx) = mpsc::channel();
        self.tx.send(Core::Query(Box::new(move |n| {
            let _ = rtx.send(f(n));
        }))).ok()?;
        rrx.recv().ok()
    }
    pub fn submit_tx(&self, tx: Transaction) -> Option<Result<AddResult, MempoolError>> {
        let (rtx, rrx) = mpsc::channel();
        self.tx.send(Core::SubmitTx(tx, rtx)).ok()?;
        rrx.recv().ok()
    }
    pub fn submit_block(&self, fb: FullBlock) -> Option<Result<AddOutcome, LedgerError>> {
        let (rtx, rrx) = mpsc::channel();
        self.tx.send(Core::SubmitBlock(Box::new(fb), rtx)).ok()?;
        rrx.recv().ok()
    }
    /// Share hallado por el minero local: se valida, se difunde y, si es bloque, se publica.
    pub fn submit_share(&self, share: Share) -> Option<Result<AddShare, ShareError>> {
        let (rtx, rrx) = mpsc::channel();
        self.tx.send(Core::SubmitShare(Box::new(share), rtx)).ok()?;
        rrx.recv().ok()
    }
    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.tx.send(Core::Stop);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

struct Conn {
    out: SyncSender<Vec<u8>>,
    stream: TcpStream,
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Arranca el nodo. Con `listen` acepta conexiones entrantes (si el nodo es `serve`).
pub fn spawn(node: Node, listen: Option<SocketAddr>) -> io::Result<NodeHandle> {
    spawn_with(node, listen, TcpOptions::default())
}

/// Identidad del nodo y claves fijadas de otros.
#[derive(Clone, Default)]
pub struct TcpOptions {
    /// Secreto estático del nodo: permite que otros fijen su clave pública (`--pin`).
    pub identity: Option<[u8; 32]>,
    /// Claves públicas que deben tener los nodos a los que marcamos. Con clave fijada, la
    /// conexión nunca baja a la variante sin identidad.
    pub pins: HashMap<SocketAddr, [u8; 32]>,
}

pub fn spawn_with(node: Node, listen: Option<SocketAddr>, opts: TcpOptions) -> io::Result<NodeHandle> {
    let (tx, rx) = mpsc::channel::<Core>();
    let stop = Arc::new(AtomicBool::new(false));
    let mut local_addr = None;
    if let Some(addr) = listen {
        let l = TcpListener::bind(addr)?;
        local_addr = Some(l.local_addr()?);
        l.set_nonblocking(true)?;
        let tx2 = tx.clone();
        let stop2 = stop.clone();
        let pending = Arc::new(AtomicUsize::new(0));
        let identity = opts.identity;
        thread::spawn(move || loop {
            if stop2.load(Ordering::SeqCst) {
                return;
            }
            match l.accept() {
                Ok((mut s, a)) => {
                    let _ = s.set_nonblocking(false);
                    if pending.fetch_add(1, Ordering::SeqCst) >= MAX_HANDSHAKES {
                        pending.fetch_sub(1, Ordering::SeqCst);
                        let _ = s.shutdown(Shutdown::Both);
                        continue;
                    }
                    let (tx3, pending2) = (tx2.clone(), pending.clone());
                    thread::spawn(move || {
                        let r = secure::handshake_auth(&mut s, false, &Auth { pin: None, identity });
                        pending2.fetch_sub(1, Ordering::SeqCst);
                        match r {
                            Ok((send, recv)) => {
                                let _ = tx3.send(Core::Incoming(Secure { stream: s, send, recv }, a));
                            }
                            Err(_) => {
                                let _ = s.shutdown(Shutdown::Both);
                            }
                        }
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(50)),
                Err(_) => thread::sleep(Duration::from_millis(200)),
            }
        });
    }
    let tx_core = tx.clone();
    let pins = Arc::new(opts.pins);
    let join = thread::spawn(move || core_loop(node, rx, tx_core, pins));
    Ok(NodeHandle { tx, join: Some(join), stop, local_addr })
}

fn core_loop(mut node: Node, rx: Receiver<Core>, tx: Sender<Core>, pins: Arc<HashMap<SocketAddr, [u8; 32]>>) {
    let mut conns: HashMap<PeerId, Conn> = HashMap::new();
    let mut next_id: PeerId = 1;
    let mut last_tick = 0u64;

    fn dispatch(conns: &mut HashMap<PeerId, Conn>, tx: &Sender<Core>, pins: &Arc<HashMap<SocketAddr, [u8; 32]>>, actions: Vec<Action>) {
        for a in actions {
            match a {
                Action::Send(p, m) => {
                    if let Some(c) = conns.get(&p) {
                        match c.out.try_send(m.encode()) {
                            Ok(()) => {}
                            Err(e) => {
                                if matches!(e, TrySendError::Full(_)) {
                                    eprintln!("[red] cierro un par que no lee (cola de envío llena: pantalla apagada o red caída en el otro extremo)");
                                }
                                let _ = c.stream.shutdown(Shutdown::Both);
                                conns.remove(&p);
                            }
                        }
                    }
                }
                Action::Disconnect(p) => {
                    if let Some(c) = conns.remove(&p) {
                        let _ = c.stream.shutdown(Shutdown::Both);
                    }
                }
                Action::Connect(addr) => {
                    let tx = tx.clone();
                    let pins = pins.clone();
                    thread::spawn(move || {
                        let sa = to_socketaddr(&addr);
                        let auth = Auth { pin: pins.get(&sa).copied(), identity: None };
                        match TcpStream::connect_timeout(&sa, CONNECT_TIMEOUT) {
                            Ok(mut s) => match secure::handshake_auth(&mut s, true, &auth) {
                                Ok((send, recv)) => {
                                    let _ = tx.send(Core::Outgoing(Secure { stream: s, send, recv }, addr));
                                }
                                Err(_) => {
                                    let _ = s.shutdown(Shutdown::Both);
                                    let _ = tx.send(Core::DialFailed(addr));
                                }
                            },
                            Err(_) => {
                                let _ = tx.send(Core::DialFailed(addr));
                            }
                        }
                    });
                }
            }
        }
    }

    fn register(
        conns: &mut HashMap<PeerId, Conn>,
        tx: &Sender<Core>,
        next_id: &mut PeerId,
        secure: Secure,
    ) -> Option<PeerId> {
        let Secure { stream, send, recv } = secure;
        let (mut send, mut recv) = (send, recv);
        let id = *next_id;
        *next_id += 1;
        let _ = stream.set_nodelay(true);
        let (wtx, wrx) = mpsc::sync_channel::<Vec<u8>>(WRITE_QUEUE);
        let mut wstream = stream.try_clone().ok()?;
        let mut rstream = stream.try_clone().ok()?;
        thread::spawn(move || {
            while let Ok(frame) = wrx.recv() {
                if wstream.write_all(&send.seal(&frame)).is_err() {
                    let _ = wstream.shutdown(Shutdown::Both);
                    return;
                }
            }
        });
        let txr = tx.clone();
        thread::spawn(move || {
            let mut dec = Decoder::new();
            'outer: loop {
                match recv.read_record(&mut rstream) {
                    Err(_) => break, // cierre, registro corrupto o repetido
                    Ok(plain) => {
                        dec.push(&plain);
                        loop {
                            match dec.next() {
                                Ok(Some(m)) => {
                                    if txr.send(Core::Frame(id, m)).is_err() {
                                        return;
                                    }
                                }
                                Ok(None) => break,
                                Err(_) => break 'outer, // trama corrupta: se cierra
                            }
                        }
                    }
                }
            }
            let _ = rstream.shutdown(Shutdown::Both);
            let _ = txr.send(Core::Closed(id));
        });
        conns.insert(id, Conn { out: wtx, stream });
        Some(id)
    }

    loop {
        // con shares por validar no se espera: se sigue con la cola
        let wait = if node.share_queue_len() > 0 { 1 } else { 500 };
        let msg = match rx.recv_timeout(Duration::from_millis(wait)) {
            Ok(m) => Some(m),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        let now = now_secs();
        if let Some(m) = msg {
            match m {
                Core::Stop => break,
                Core::Incoming(s, sa) => {
                    if let Some(id) = register(&mut conns, &tx, &mut next_id, s) {
                        let acts = node.handle(now, Event::Connected { peer: id, addr: to_netaddr(sa), inbound: true });
                        dispatch(&mut conns, &tx, &pins, acts);
                    }
                }
                Core::Outgoing(s, addr) => {
                    if let Some(id) = register(&mut conns, &tx, &mut next_id, s) {
                        let acts = node.handle(now, Event::Connected { peer: id, addr, inbound: false });
                        dispatch(&mut conns, &tx, &pins, acts);
                    }
                }
                Core::DialFailed(addr) => {
                    let acts = node.handle(now, Event::ConnectFailed(addr));
                    dispatch(&mut conns, &tx, &pins, acts);
                }
                Core::Frame(id, m) => {
                    if conns.contains_key(&id) {
                        let acts = node.handle(now, Event::Message(id, m));
                        dispatch(&mut conns, &tx, &pins, acts);
                    }
                }
                Core::Closed(id) => {
                    conns.remove(&id);
                    let acts = node.handle(now, Event::Disconnected(id));
                    dispatch(&mut conns, &tx, &pins, acts);
                }
                Core::Query(f) => f(&mut node),
                Core::SubmitTx(t, reply) => {
                    let (r, acts) = node.submit_tx(now, t);
                    dispatch(&mut conns, &tx, &pins, acts);
                    let _ = reply.send(r);
                }
                Core::SubmitBlock(fb, reply) => {
                    let (r, acts) = node.submit_block(now, *fb);
                    dispatch(&mut conns, &tx, &pins, acts);
                    let _ = reply.send(r);
                }
                Core::SubmitShare(sh, reply) => {
                    let (r, acts) = node.submit_share(now, *sh);
                    dispatch(&mut conns, &tx, &pins, acts);
                    let _ = reply.send(r);
                }
            }
        }
        for e in node.take_events() {
            eprintln!("[red] {e}");
        }
        if node.share_queue_len() > 0 {
            let acts = node.work(now);
            dispatch(&mut conns, &tx, &pins, acts);
        }
        if now != last_tick {
            last_tick = now;
            let acts = node.handle(now, Event::Tick);
            dispatch(&mut conns, &tx, &pins, acts);
        }
    }
    for (_, c) in conns.drain() {
        let _ = c.stream.shutdown(Shutdown::Both);
    }
}
