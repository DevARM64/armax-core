//! Arranque y operación del nodo.

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use armax_chain::{Address, DamperParams, SkipPow};
use armax_keys::address::{decode, encode};
use armax_keys::ed25519::Keypair;
use armax_keys::rng::fill_os_random;
use armax_ledger::Ledger;
use armax_mempool::{AddResult, Mempool, MempoolConfig};
use armax_net::node::{Node, NodeConfig};
use armax_net::tcp::{to_netaddr, NodeHandle};
use armax_store::Store;
use armax_thermal::ThermalConfig;
use armax_vm::Native;

use crate::miner::{Miner, MinerConfig, SharedSensors};
use crate::network::Network;
use crate::walletfile::WalletFile;
use crate::{format_amount, hex, pay};

pub struct AppConfig {
    pub network: Network,
    pub data_dir: PathBuf,
    pub listen: Option<SocketAddr>,
    pub connect: Vec<SocketAddr>,
    pub wallet: Option<PathBuf>,
    /// Semilla Ed25519 ya derivada (la app Android desbloquea la cartera con el Keystore y la
    /// entrega aquí). Tiene prioridad sobre `wallet`.
    pub identity_seed: Option<[u8; 32]>,
    pub mine: bool,
    /// Participa en la sharechain (P2Pool): retransmite shares y, con `mine`, mina shares.
    pub pool: bool,
    pub threads: usize,
    pub use_governor: bool,
    pub thermal: ThermalConfig,
    /// No re-verificar el PoW de lo ya guardado al arrancar (más rápido; confía en el checksum).
    pub trust_store: bool,
    /// Sensores empujados por la app (ver `miner::SharedSensors`).
    pub sensors: Option<SharedSensors>,
    /// Secreto estático del nodo. Si es `None` y el nodo escucha, se lee/crea `DATA/node.key`.
    pub node_key: Option<[u8; 32]>,
    /// Claves públicas fijadas de los nodos a los que se marca (`--pin IP:PUERTO=CLAVE`).
    pub pins: Vec<(SocketAddr, [u8; 32])>,
}

/// Instantánea del estado, para la interfaz (texto en el CLI, JSON en el puente).
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub height: u64,
    pub tip: [u8; 32],
    pub peers: usize,
    pub ready_peers: usize,
    pub known_addrs: usize,
    pub mempool: usize,
    pub syncing: bool,
    pub balance: Option<u128>,
    pub spendable: Option<u128>,
    pub miner: Option<MinerSnapshot>,
    pub pool: Option<PoolSnapshot>,
}

#[derive(Clone, Debug)]
pub struct MinerSnapshot {
    pub threads: usize,
    pub reason: String,
    pub hashrate: f64,
    pub blocks_found: u64,
    pub battery_temp_c: Option<f64>,
    pub shares_found: u64,
}

/// Estado de la sharechain (solo con `pool`).
#[derive(Clone, Debug)]
pub struct PoolSnapshot {
    /// Shares en la sharechain local.
    pub shares: usize,
    /// Shares retenidos esperando a su anterior o a su bloque padre.
    pub orphans: usize,
    /// Parte (ppm) de nuestra dirección en la ventana actual.
    pub my_ppm: Option<u32>,
}

pub struct App {
    pub handle: Arc<NodeHandle>,
    pub address: Option<Address>,
    key: Option<Keypair>,
    miner: Option<Miner>,
    pub network: Network,
    sent_log: crate::sentlog::SentLog,
}

/// Secreto estático del nodo: 32 bytes aleatorios en un archivo privado (0600).
fn load_or_create_node_key(path: &std::path::Path) -> Result<[u8; 32], String> {
    if let Ok(b) = fs::read(path) {
        return <[u8; 32]>::try_from(b.as_slice()).map_err(|_| format!("{}: tamaño inválido", path.display()));
    }
    let mut k = [0u8; 32];
    fill_os_random(&mut k).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        f.write_all(&k).map_err(|e| e.to_string())?;
    }
    #[cfg(not(unix))]
    fs::write(path, k).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(k)
}

fn wall() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl App {
    pub fn start(cfg: AppConfig) -> Result<App, String> {
        fs::create_dir_all(&cfg.data_dir).map_err(|e| format!("{}: {e}", cfg.data_dir.display()))?;
        let (address, key) = match (&cfg.identity_seed, &cfg.wallet) {
            (Some(seed), _) => {
                let kp = Keypair::from_seed(*seed);
                (Some(armax_keys::address::address_from_public_key(&kp.public_key())), Some(kp))
            }
            (None, Some(p)) => {
                let w = WalletFile::open(p)?;
                (Some(w.address()?), Some(w.keypair()?))
            }
            (None, None) => (None, None),
        };
        if cfg.mine && address.is_none() {
            return Err("para minar hace falta una cartera".into());
        }

        let params = cfg.network.params();
        let mut ledger = Ledger::with_maturity(DamperParams::MAINNET, cfg.network.genesis(), 2, cfg.network.coinbase_maturity()).map_err(|e| format!("{e}"))?;
        let mut pow = armax_chain::VmPow::<Native>::new(params).map_err(|e| format!("memoria para el PoW: {e:?}"))?;
        let db = cfg.data_dir.join("blocks.db");
        let t = std::time::Instant::now();
        let opened = if cfg.trust_store {
            Store::open(&db, &mut ledger, wall(), &mut SkipPow)
        } else {
            Store::open(&db, &mut ledger, wall(), &mut pow)
        };
        let (store, report) = opened.map_err(|e| format!("{}: {e}", db.display()))?;
        println!(
            "red {} | disco: {} bloques cargados en {:.1} s, altura {}{}",
            cfg.network.name(),
            report.blocks_loaded,
            t.elapsed().as_secs_f64(),
            ledger.tip_height(),
            match &report.reason {
                Some(r) => format!(" | se recortaron {} bytes dañados ({r})", report.truncated_bytes),
                None => String::new(),
            }
        );

        let mut nonce = [0u8; 8];
        fill_os_random(&mut nonce).map_err(|e| e.to_string())?;
        let ncfg = NodeConfig {
            serve: cfg.listen.is_some(),
            listen_port: cfg.listen.map_or(0, |a| a.port()),
            seeds: cfg.connect.iter().map(|a| to_netaddr(*a)).collect(),
            // con el PoW reducido de `fast` las cabeceras son baratas; con el de consenso cada una
            // cuesta una ejecución de la VM y se validan pocas por paso
            headers_per_step: if cfg.network == Network::Fast { 1_000 } else { 4 },
            ..NodeConfig::default()
        };
        let mut node = Node::new(
            ledger,
            Mempool::new(MempoolConfig::default()),
            Some(store),
            Box::new(pow),
            ncfg,
            u64::from_le_bytes(nonce),
        );
        if cfg.pool {
            node.enable_sharechain(cfg.network.share_params());
            // la sharechain sobrevive a los reinicios; si no se puede abrir, se sigue sin guardar
            let sp = cfg.data_dir.join("shares.db");
            let t = std::time::Instant::now();
            match node.enable_share_store(&sp, cfg.trust_store, wall()) {
                Ok(r) => println!(
                    "disco: {} shares cargados en {:.1} s{}{}{}",
                    r.loaded,
                    t.elapsed().as_secs_f64(),
                    if r.skipped > 0 { format!(" ({} descartados)", r.skipped) } else { String::new() },
                    if r.compacted { " | archivo compactado" } else { "" },
                    match &r.reason {
                        Some(why) => format!(" | se recortaron {} bytes dañados ({why})", r.truncated_bytes),
                        None => String::new(),
                    }
                ),
                Err(e) => println!("aviso: no se guardarán los shares en disco ({e})"),
            }
        }
        let identity = match (cfg.node_key, cfg.listen) {
            (Some(k), _) => Some(k),
            (None, Some(_)) => Some(load_or_create_node_key(&cfg.data_dir.join("node.key"))?),
            (None, None) => None,
        };
        if let Some(k) = &identity {
            println!("clave pública del nodo: {} (los demás la fijan con --pin IP:PUERTO=CLAVE)", hex(&armax_keys::x25519::public_key(k)));
        }
        let opts = armax_net::tcp::TcpOptions { identity, pins: cfg.pins.iter().copied().collect() };
        let handle = Arc::new(armax_net::tcp::spawn_with(node, cfg.listen, opts).map_err(|e| format!("no se pudo escuchar: {e}"))?);
        if let Some(a) = handle.local_addr {
            println!("escuchando en {a}");
        }
        let miner = if cfg.mine {
            let mc = MinerConfig {
                params,
                max_threads: cfg.threads.max(1),
                pool: cfg.pool,
                use_governor: cfg.use_governor,
                thermal: cfg.thermal,
                sensors: cfg.sensors.clone(),
            };
            Some(Miner::start(handle.clone(), address.unwrap(), mc))
        } else {
            None
        };
        Ok(App { handle, address, key, miner, network: cfg.network, sent_log: crate::sentlog::SentLog::new(cfg.data_dir.join("sent.log")) })
    }

    pub fn balance(&self) -> Result<String, String> {
        let a = self.address.ok_or("no hay cartera (--wallet)")?;
        let (total, spendable) = self
            .handle
            .query(move |n| (n.ledger().balance_of(&a), pay::spendable(n.ledger(), n.pool(), &a)))
            .ok_or("el nodo no responde")?;
        Ok(format!("{} ARM (gastable ahora: {} ARM)", format_amount(total), format_amount(spendable)))
    }

    /// Las `limit` entradas más recientes del historial de la cartera (pendientes primero).
    pub fn history(&self, limit: usize) -> Result<Vec<crate::history::Entry>, String> {
        let a = self.address.ok_or("no hay cartera (--wallet)")?;
        let mut entries = self
            .handle
            .query(move |n| crate::history::history(n.ledger(), n.pool(), &a, limit))
            .ok_or_else(|| "el nodo no responde".to_string())?;
        let fees = self.sent_log.load();
        for e in entries.iter_mut() {
            if e.kind == crate::history::Kind::Sent {
                e.fee = e.txid.and_then(|t| fees.get(&t).copied());
            }
        }
        Ok(entries)
    }

    pub fn snapshot(&self) -> Snapshot {
        let a = self.address;
        let (height, tip, peers, ready_peers, mempool, syncing, known_addrs, balance, spendable) = self
            .handle
            .query(move |n| {
                (
                    n.ledger().tip_height(),
                    n.ledger().tip_id(),
                    n.peer_count(),
                    n.ready_peer_count(),
                    n.pool().len(),
                    n.is_syncing(),
                    n.known_addresses(),
                    a.map(|a| n.ledger().balance_of(&a)),
                    a.map(|a| pay::spendable(n.ledger(), n.pool(), &a)),
                )
            })
            .unwrap_or((0, [0; 32], 0, 0, 0, false, 0, None, None));
        let miner = self.miner.as_ref().map(|m| {
            let st = m.status();
            MinerSnapshot {
                threads: st.threads,
                reason: st.reason,
                hashrate: m.hashrate(),
                blocks_found: st.blocks_found,
                battery_temp_c: st.battery_temp_c,
                shares_found: st.shares_found,
            }
        });
        let me = self.address;
        let pool = self
            .handle
            .query(move |n| {
                n.sharechain().map(|sc| PoolSnapshot {
                    shares: sc.len(),
                    orphans: n.share_orphan_count(),
                    my_ppm: me.map(|a| sc.miner_ppm(&a)),
                })
            })
            .flatten();
        Snapshot { height, tip, peers, ready_peers, known_addrs, mempool, syncing, balance, spendable, miner, pool }
    }

    pub fn status(&self) -> String {
        let n = self.snapshot();
        let mut s = format!(
            "altura {} | punta {}… | pares {}/{} (direcciones conocidas {}){} | mempool {}",
            n.height,
            &hex(&n.tip)[..12],
            n.ready_peers,
            n.peers,
            n.known_addrs,
            if n.syncing { " | sincronizando" } else { "" },
            n.mempool
        );
        if let Some(b) = n.balance {
            s += &format!(" | saldo {} ARM", format_amount(b));
        }
        if let Some(m) = &n.miner {
            s += &format!(
                " | minando: {} hilos ({}) {:.1} H/s, {} bloques{}",
                m.threads,
                m.reason,
                m.hashrate,
                m.blocks_found,
                m.battery_temp_c.map_or(String::new(), |t| format!(", batería {t:.1} °C"))
            );
        }
        if let Some(p) = &n.pool {
            s += &format!(" | pool: {} shares", p.shares);
            if p.orphans > 0 {
                s += &format!(" ({} huérfanos)", p.orphans);
            }
            if let Some(ppm) = p.my_ppm {
                s += &format!(", tu parte {:.1} %", ppm as f64 / 10_000.0);
            }
            if let Some(m) = &n.miner {
                s += &format!(", {} shares hallados", m.shares_found);
            }
        }
        s
    }

    pub fn send(&self, to: &str, amount: u64, fee: Option<u64>) -> Result<String, String> {
        let from = self.address.ok_or("no hay cartera (--wallet)")?;
        let key = self.key.as_ref().ok_or("no hay cartera (--wallet)")?;
        let to = decode(to).map_err(|e| format!("dirección inválida: {e:?}"))?;
        // la transacción se firma fuera del hilo del nodo; el nodo solo la admite y la reenvía
        let tx = {
            let key_seed = key.seed();
            let r = self
                .handle
                .query(move |n| {
                    let k = Keypair::from_seed(key_seed);
                    let tx = pay::build_payment(n.ledger(), n.pool(), &k, &from, to, amount, fee)?;
                    let paid = pay::fee_of(n.ledger(), &tx);
                    Ok::<_, String>((tx, paid))
                })
                .ok_or("el nodo no responde")?;
            r?
        };
        let (tx, paid_fee) = tx;
        let txid = tx.txid();
        match self.handle.submit_tx(tx).ok_or("el nodo no responde")? {
            Ok(AddResult::Added) | Ok(AddResult::AddedDisplacing(_)) => {
                if let Some(f) = paid_fee {
                    self.sent_log.record(&txid, f);
                }
                Ok(format!("enviada: {}", hex(&txid)))
            }
            Ok(AddResult::AlreadyKnown) => Ok("ya estaba en el mempool".into()),
            Err(e) => Err(format!("el mempool la rechazó: {e:?}")),
        }
    }

    pub fn address_string(&self) -> Option<String> {
        self.address.as_ref().map(encode)
    }

    pub fn shutdown(mut self) {
        if let Some(m) = self.miner.take() {
            m.stop();
        }
        if let Ok(h) = Arc::try_unwrap(self.handle) {
            h.shutdown();
        }
    }
}
