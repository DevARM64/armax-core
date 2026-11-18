use std::io::BufRead;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use armax_keys::address::encode;
use armax_node::app::{App, AppConfig};
use armax_node::network::Network;
use armax_node::walletfile::WalletFile;
use armax_node::parse_amount;
use armax_thermal::ThermalConfig;

const HELP: &str = "\
armax-node — nodo de ARMax (red de desarrollo)

USO
  armax-node new-wallet --wallet ARCHIVO
  armax-node address    --wallet ARCHIVO
  armax-node run --data DIR --network fast|devnet [opciones]

OPCIONES DE `run`
  --listen IP:PUERTO     acepta conexiones entrantes (nodo de servicio)
  --connect IP:PUERTO    se conecta a este nodo (repetible)
  --pin IP:PUERTO=CLAVE  exige que ese nodo tenga esa clave pública (la imprime al arrancar con --listen);
                         con clave fijada la conexión nunca baja a modo sin identidad (repetible)
  --wallet ARCHIVO       cartera (para minar y enviar)
  --mine                 mina hacia la dirección de la cartera
  --pool                 participa en la sharechain (P2Pool): retransmite shares y, con --mine, mina shares
                         y reparte cada bloque entre los mineros recientes (todos los nodos de la red deben usarlo)
  --threads N            hilos máximos de minado (2 por defecto)
  --any-power            minar también sin cargador (batería ≥ 15 %, o el valor de --min-battery)
  --min-battery N        con --any-power, batería mínima (%) para minar sin cargador (15 por defecto)
  --no-temp              minar aunque no se lea la temperatura
  --no-governor          sin gobernador térmico (solo para pruebas en PC)
  --trust-store          no re-verificar el PoW del disco al arrancar

COMANDOS EN `run` (escríbelos y Enter)
  status | balance | address | send DIRECCIÓN CANTIDAD [COMISIÓN_EN_UNIDADES] | quit

ADVERTENCIA: la cartera es de desarrollo (sin cifrar). No la uses con fondos reales.";

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned()
}
fn arg_values(args: &[String], flag: &str) -> Vec<String> {
    args.iter().enumerate().filter(|(_, a)| *a == flag).filter_map(|(i, _)| args.get(i + 1)).cloned().collect()
}
fn has(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}
fn resolve(s: &str) -> Result<SocketAddr, String> {
    s.to_socket_addrs().map_err(|e| format!("{s}: {e}"))?.next().ok_or_else(|| format!("{s}: sin dirección"))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = real_main(&args) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn real_main(args: &[String]) -> Result<(), String> {
    match args.first().map(|s| s.as_str()) {
        Some("new-wallet") => {
            let path = PathBuf::from(arg_value(args, "--wallet").ok_or("falta --wallet ARCHIVO")?);
            let (w, phrase) = WalletFile::create(&path)?;
            println!("Cartera creada en {}", path.display());
            println!("Dirección: {}", encode(&w.address()?));
            println!("\nFRASE DE RESPALDO (anótala; no se vuelve a mostrar):\n  {phrase}");
            println!("\nCartera de desarrollo: el archivo no está cifrado.");
            Ok(())
        }
        Some("address") => {
            let path = PathBuf::from(arg_value(args, "--wallet").ok_or("falta --wallet ARCHIVO")?);
            println!("{}", encode(&WalletFile::open(&path)?.address()?));
            Ok(())
        }
        Some("run") => run(args),
        _ => {
            println!("{HELP}");
            Ok(())
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let network = Network::parse(&arg_value(args, "--network").ok_or("falta --network fast|devnet")?)
        .ok_or("red desconocida (usa fast o devnet)")?;
    let data_dir = PathBuf::from(arg_value(args, "--data").ok_or("falta --data DIR")?);
    let listen = arg_value(args, "--listen").map(|s| resolve(&s)).transpose()?;
    let connect = arg_values(args, "--connect").iter().map(|s| resolve(s)).collect::<Result<Vec<_>, _>>()?;
    let mut pins = Vec::new();
    for p in arg_values(args, "--pin") {
        let (addr, key) = p.split_once('=').ok_or("--pin espera IP:PUERTO=CLAVE")?;
        let key: [u8; 32] = armax_node::unhex(key).and_then(|v| v.try_into().ok()).ok_or("--pin: la clave debe ser 64 caracteres hex")?;
        pins.push((resolve(addr)?, key));
    }
    let mut thermal = ThermalConfig::default();
    thermal.require_charging = !has(args, "--any-power");
    thermal.allow_without_temperature = has(args, "--no-temp");
    if let Some(v) = arg_value(args, "--min-battery") {
        let pct: u8 = v.parse().ok().filter(|p| *p <= 100).ok_or("--min-battery espera un número de 0 a 100")?;
        thermal.min_battery_pct_unplugged = pct;
    }
    let threads: usize = arg_value(args, "--threads").map(|s| s.parse().map_err(|_| "--threads inválido")).transpose()?.unwrap_or(2);
    thermal.max_threads = threads.min(255) as u8;
    if network == Network::Fast {
        thermal.mem_per_thread_mib = 1;
        thermal.mem_headroom_mib = 0;
    }
    let cfg = AppConfig {
        network,
        data_dir,
        listen,
        connect,
        wallet: arg_value(args, "--wallet").map(PathBuf::from),
        identity_seed: None,
        mine: has(args, "--mine"),
        pool: has(args, "--pool"),
        threads,
        use_governor: !has(args, "--no-governor"),
        thermal,
        trust_store: has(args, "--trust-store"),
        sensors: None,
        node_key: None,
        pins,
    };
    let app = App::start(cfg)?;
    if let Some(a) = app.address_string() {
        println!("dirección: {a}");
    }
    println!("escribe `status`, `balance`, `send DIRECCIÓN CANTIDAD`, `quit`. Ctrl-C también sale (el disco queda consistente).");

    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                return;
            }
        }
    });
    let mut since_status = 0u32;
    loop {
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(line) => {
                let w: Vec<&str> = line.split_whitespace().collect();
                match w.as_slice() {
                    ["quit"] | ["exit"] => break,
                    ["status"] => println!("{}", app.status()),
                    ["balance"] => println!("{}", app.balance().unwrap_or_else(|e| format!("error: {e}"))),
                    ["address"] => println!("{}", app.address_string().unwrap_or_else(|| "sin cartera".into())),
                    ["send", to, amount, rest @ ..] => {
                        let r = parse_amount(amount).and_then(|a| {
                            let fee = rest.first().map(|f| f.parse::<u64>().map_err(|_| "comisión inválida".to_string())).transpose()?;
                            app.send(to, a, fee)
                        });
                        match r {
                            Ok(m) => println!("{m}"),
                            Err(e) => println!("error: {e}"),
                        }
                    }
                    [] => {}
                    _ => println!("comando desconocido"),
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                since_status += 1;
                if since_status >= 30 {
                    since_status = 0;
                    println!("{}", app.status());
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // stdin cerrado (p. ej. en segundo plano): sigue funcionando hasta Ctrl-C
                std::thread::sleep(Duration::from_secs(30));
                println!("{}", app.status());
            }
        }
    }
    app.shutdown();
    Ok(())
}
