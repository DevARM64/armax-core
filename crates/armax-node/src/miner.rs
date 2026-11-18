//! Minero: hilos de trabajo + un coordinador.
//!
//! * El **coordinador** pide al nodo una plantilla (con las transacciones del mempool y el
//!   coinbase para la dirección del minero) cada vez que cambia la punta, o cada 30 s para
//!   refrescar la hora y las transacciones. Publica el trabajo y recoge los nonces hallados,
//!   que entrega al nodo como un bloque más (se valida igual que uno ajeno).
//! * Con `pool`, la plantilla es la de un **share** de la sharechain (P2Pool): el coinbase reparte
//!   la recompensa entre los mineros recientes y los hilos buscan nonces contra el umbral fácil
//!   (`ratio` veces menos difícil). Cada share hallado se entrega al nodo, que lo difunde y, si
//!   además cumple el target del bloque, lo publica como bloque. Si no hay plantilla de share
//!   (p. ej. la sharechain va por delante de nuestros bloques) se mina un bloque en solitario.
//! * Cada **hilo de trabajo** prueba nonces en su propio rango. Cuando el gobernador térmico
//!   lo deja en pausa libera sus 384 MiB.
//! * El **gobernador** (`armax-thermal`) lee batería, carga, temperatura y memoria cada 10 s y
//!   decide cuántos hilos corren.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use armax_chain::Address;
use armax_ledger::FullBlock;
use armax_net::tcp::NodeHandle;
use armax_pow::consensus::op_table_for_seed;
use armax_pow::validate::{mine, mine_at};
use armax_pow::{BlockHeader, U256};
use armax_share::{share_target, AddShare, Share, MAX_SHARE_TXS, MAX_SHARE_TX_BYTES};
use armax_thermal::{AutoSource, Governor, SensorSource, Sensors, ThermalConfig};
use armax_vm::{Native, OpTable, Params, Scratchpad};

const REFRESH_SECS: u64 = 30;
const GOVERNOR_SECS: u64 = 10;

/// Lecturas que empuja la app Android (BatteryManager, PowerManager…). Sustituye a la lectura de
/// `/sys` y de Termux:API. Lo que no se empuje (`None`) se completa donde se pueda (memoria libre
/// se lee de `/proc/meminfo`).
pub type SharedSensors = Arc<Mutex<Sensors>>;

struct PushedSource(SharedSensors);

impl SensorSource for PushedSource {
    fn read(&mut self, now_s: u64) -> Sensors {
        let mut s = *self.0.lock().unwrap();
        s.now_s = now_s;
        if s.mem_available_mib.is_none() {
            s.mem_available_mib = armax_vm::mem::mem_available_bytes().map(|b| b >> 20);
        }
        s
    }
}

#[derive(Clone)]
pub struct MinerConfig {
    pub params: Params,
    pub max_threads: usize,
    /// Minar shares de la sharechain en vez de bloques en solitario.
    pub pool: bool,
    pub use_governor: bool,
    pub thermal: ThermalConfig,
    /// Sensores empujados desde fuera; `None` = leer el dispositivo (sysfs/Termux:API).
    pub sensors: Option<SharedSensors>,
}

#[derive(Clone, Debug, Default)]
pub struct MinerStatus {
    pub threads: usize,
    pub reason: String,
    pub blocks_found: u64,
    /// Shares hallados y aceptados por el nodo (los que además fueron bloque cuentan en ambos).
    pub shares_found: u64,
    pub battery_temp_c: Option<f64>,
}

struct Job {
    gen: u64,
    tip: [u8; 32],
    /// Punta de la sharechain sobre la que se construyó (`None` en solitario).
    share_tip: Option<[u8; 32]>,
    /// Umbral fácil de los shares; `None` = se busca un bloque en solitario.
    share_target: Option<U256>,
    built_at: Instant,
    header: BlockHeader,
    block: FullBlock,
    table: Arc<OpTable>,
}

struct Shared {
    stop: AtomicBool,
    desired: AtomicUsize,
    gen: AtomicU64,
    attempts: AtomicU64,
    job: Mutex<Option<Arc<Job>>>,
    status: Mutex<MinerStatus>,
}

pub struct Miner {
    shared: Arc<Shared>,
    joins: Vec<JoinHandle<()>>,
    last: Mutex<(Instant, u64)>,
}

fn wall() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Miner {
    pub fn start(handle: Arc<NodeHandle>, address: Address, cfg: MinerConfig) -> Miner {
        let shared = Arc::new(Shared {
            stop: AtomicBool::new(false),
            desired: AtomicUsize::new(if cfg.use_governor { 0 } else { cfg.max_threads }),
            gen: AtomicU64::new(0),
            attempts: AtomicU64::new(0),
            job: Mutex::new(None),
            status: Mutex::new(MinerStatus::default()),
        });
        let (found_tx, found_rx) = mpsc::channel::<(u64, u64)>();
        let mut joins = vec![];
        let params = cfg.params;
        for id in 0..cfg.max_threads {
            let (sh, tx) = (shared.clone(), found_tx.clone());
            joins.push(thread::spawn(move || worker(id, params, sh, tx)));
        }
        let sh = shared.clone();
        joins.push(thread::spawn(move || coordinator(handle, address, cfg, sh, found_rx)));
        Miner { shared, joins, last: Mutex::new((Instant::now(), 0)) }
    }

    pub fn status(&self) -> MinerStatus {
        self.shared.status.lock().unwrap().clone()
    }

    /// H/s desde la última consulta.
    pub fn hashrate(&self) -> f64 {
        let n = self.shared.attempts.load(Relaxed);
        let mut last = self.last.lock().unwrap();
        let dt = last.0.elapsed().as_secs_f64().max(0.001);
        let r = (n - last.1) as f64 / dt;
        *last = (Instant::now(), n);
        r
    }

    pub fn stop(mut self) {
        self.shared.stop.store(true, Relaxed);
        for j in self.joins.drain(..) {
            let _ = j.join();
        }
    }
}

fn worker(id: usize, params: Params, sh: Arc<Shared>, found: Sender<(u64, u64)>) {
    let mut sp: Option<Scratchpad> = None;
    let mut done_gen = 0u64;
    while !sh.stop.load(Relaxed) {
        let job = sh.job.lock().unwrap().clone();
        let active = id < sh.desired.load(Relaxed);
        let job = match (active, job) {
            (true, Some(j)) if j.gen != done_gen => j,
            (true, Some(_)) => {
                thread::sleep(Duration::from_millis(100));
                continue;
            }
            _ => {
                sp = None; // pausado o sin trabajo: libera la memoria
                thread::sleep(Duration::from_millis(300));
                continue;
            }
        };
        if sp.is_none() {
            match Scratchpad::new(params.scratch_bytes) {
                Ok(s) => sp = Some(s),
                Err(_) => {
                    thread::sleep(Duration::from_secs(1));
                    continue;
                }
            }
        }
        let scratch = sp.as_mut().unwrap().as_mut_slice();
        let mut nonce = ((id as u64) << 56) ^ job.gen.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        loop {
            if sh.stop.load(Relaxed) || id >= sh.desired.load(Relaxed) || sh.gen.load(Relaxed) != job.gen {
                break;
            }
            let hit = match &job.share_target {
                Some(t) => mine_at::<Native>(&job.header, t, &params, &job.table, scratch, nonce, 1, &mut || false),
                None => mine::<Native>(&job.header, &params, &job.table, scratch, nonce, 1, &mut || false),
            };
            if let Some((n, _)) = hit {
                let _ = found.send((job.gen, n));
                done_gen = job.gen;
                break;
            }
            sh.attempts.fetch_add(1, Relaxed);
            nonce = nonce.wrapping_add(1);
        }
    }
}

/// Plantilla sobre la punta actual: (bloque o share, semilla de época, id de la punta, punta de la
/// sharechain, umbral de share).
type Template = (FullBlock, [u8; 32], [u8; 32], Option<[u8; 32]>, Option<U256>);

fn coordinator(handle: Arc<NodeHandle>, addr: Address, cfg: MinerConfig, sh: Arc<Shared>, found_rx: Receiver<(u64, u64)>) {
    let start = Instant::now();
    let mut gov = Governor::new(cfg.thermal).ok().filter(|_| cfg.use_governor);
    let mut src: Box<dyn SensorSource> = match &cfg.sensors {
        Some(shared) => Box::new(PushedSource(shared.clone())),
        None => Box::new(AutoSource::new()),
    };
    let mut last_gov: Option<Instant> = None;
    let mut cached: Option<([u8; 32], Arc<OpTable>)> = None;
    let mut force = true;

    while !sh.stop.load(Relaxed) {
        // 1. nonces hallados
        while let Ok((g, nonce)) = found_rx.try_recv() {
            let job = sh.job.lock().unwrap().clone();
            if let Some(job) = job.filter(|j| j.gen == g) {
                if job.share_target.is_some() {
                    let share = Share { header: job.header.with_nonce(nonce), coinbase: job.block.block.coinbase.clone(), txs: job.block.txs.clone() };
                    match handle.submit_share(share) {
                        Some(Ok(AddShare::Added { is_block, .. })) => {
                            let mut st = sh.status.lock().unwrap();
                            st.shares_found += 1;
                            if is_block {
                                st.blocks_found += 1;
                            }
                        }
                        Some(Ok(AddShare::AlreadyKnown)) => {}
                        Some(Err(e)) => eprintln!("el share minado fue rechazado: {e:?}"),
                        None => return,
                    }
                } else {
                    let mut fb = job.block.clone();
                    fb.block.header.nonce = nonce;
                    match handle.submit_block(fb) {
                        Some(Ok(_)) => sh.status.lock().unwrap().blocks_found += 1,
                        Some(Err(e)) => eprintln!("el bloque minado fue rechazado: {e}"),
                        None => return,
                    }
                }
                force = true;
            }
        }
        // 2. gobernador térmico
        if let Some(g) = gov.as_mut() {
            if last_gov.map_or(true, |t| t.elapsed() >= Duration::from_secs(GOVERNOR_SECS)) {
                last_gov = Some(Instant::now());
                let s = src.read(start.elapsed().as_secs());
                let d = g.update(&s);
                sh.desired.store((d.threads as usize).min(cfg.max_threads), Relaxed);
                let mut st = sh.status.lock().unwrap();
                st.threads = d.threads as usize;
                st.reason = format!("{:?}", d.reason);
                st.battery_temp_c = s.battery_temp_c;
            }
        } else {
            let mut st = sh.status.lock().unwrap();
            st.threads = cfg.max_threads;
            st.reason = "sin gobernador".into();
        }
        // 3. ¿hace falta una plantilla nueva?
        let (tip, share_tip) = match handle.query(|n| (n.ledger().tip_id(), n.sharechain().and_then(|s| s.tip()))) {
            Some(t) => t,
            None => return,
        };
        let stale = match sh.job.lock().unwrap().as_ref() {
            // un share nuevo (propio o ajeno) cambia el reparto: la plantilla anterior ya no vale
            Some(j) => {
                j.tip != tip
                    || (cfg.pool && j.share_tip != share_tip)
                    || j.built_at.elapsed() >= Duration::from_secs(REFRESH_SECS)
            }
            None => true,
        };
        if stale || force {
            force = false;
            let pool = cfg.pool;
            let tpl: Option<Template> = handle
                .query(move |n| {
                    let tip = n.ledger().tip_id();
                    let h = n.ledger().tip_height() + 1;
                    let tip_ts = n.ledger().chain().header(&tip).map(|x| x.timestamp).unwrap_or(0);
                    let ts = wall().max(tip_ts + 1);
                    if pool && n.sharechain().is_some() {
                        // las transacciones del mempool que caben en un share, con sus comisiones
                        let cands = n.pool().candidates();
                        let (txs, fees) = n.ledger_mut().select_txs_within(&cands, MAX_SHARE_TXS, MAX_SHARE_TX_BYTES);
                        let sc = n.sharechain().unwrap();
                        let chain = n.ledger().chain();
                        // si algo no encaja, un share sin transacciones sigue siendo válido
                        let s = sc
                            .template_with(chain, tip, addr, ts, txs, fees)
                            .or_else(|_| sc.template(chain, tip, addr, ts));
                        if let Ok(s) = s {
                            let st = share_target(&s.header.target, sc.params().ratio);
                            let seed = chain.epoch_seed_for(&tip, h).ok()?;
                            let fb = FullBlock { block: s.to_block(), txs: s.txs };
                            return Some((fb, seed, tip, sc.tip(), Some(st)));
                        }
                    }
                    let cands = n.pool().candidates();
                    let fb = n.ledger_mut().build_template(&[(addr, 1_000_000)], ts, b"armax".to_vec(), &cands).ok()?;
                    let seed = n.ledger().chain().epoch_seed_for(&tip, h).ok()?;
                    Some((fb, seed, tip, None, None))
                })
                .flatten();
            if let Some((fb, seed, tip, share_tip, share_target)) = tpl {
                let table = match &cached {
                    Some((s, t)) if *s == seed => t.clone(),
                    _ => {
                        let t = Arc::new(op_table_for_seed(&seed));
                        cached = Some((seed, t.clone()));
                        t
                    }
                };
                let gen = sh.gen.fetch_add(1, Relaxed) + 1;
                let header = fb.block.header.clone();
                *sh.job.lock().unwrap() = Some(Arc::new(Job { gen, tip, share_tip, share_target, built_at: Instant::now(), header, block: fb, table }));
            }
        }
        thread::sleep(Duration::from_millis(250));
    }
}
