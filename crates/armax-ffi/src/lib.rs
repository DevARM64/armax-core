//! Interfaz C del nodo ARMax, pensada para la app Android (Kotlin + JNA).
//!
//! # Por qué C y no UniFFI/JNI
//! El núcleo no tiene dependencias externas y esta interfaz tampoco: es una ABI C simple que
//! Kotlin consume con JNA (`Library` + `Callback`), sin generación de código. Si más adelante se
//! prefiere UniFFI, se escribe encima de este mismo conjunto de funciones.
//!
//! # Convenciones
//! * Todas las funciones devuelven `i32`: `0` = éxito; negativo = error (`ARMAX_ERR_*`). Las que
//!   escriben texto devuelven el número de bytes escritos (≥ 0) o un error. El detalle del último
//!   error está en `armax_last_error` (por hilo).
//! * Los textos de salida son UTF-8 terminados en NUL, en un búfer del llamador. Si no cabe: `-2`.
//! * Ninguna función deja pasar un pánico de Rust hacia el llamador (`-6`).
//! * La **bóveda** (`ArmaxVault`) son dos callbacks que Kotlin implementa con una clave AES-GCM
//!   del Android Keystore: `seal(plano) → sellado` y `open(sellado) → plano`. La entropía de la
//!   cartera solo existe en claro dentro de estas llamadas; lo que se guarda en disco es el sellado.
//! * El nodo recibe sus lecturas de batería/carga/pantalla/memoria con `armax_node_push_sensors`
//!   (desde `BatteryManager`/`PowerManager`). Mientras no lleguen, el gobernador mantiene el
//!   minero en pausa (falla seguro).
//!
//! # Seguridad de memoria
//! `armax_node_stop` debe llamarse una sola vez por manejador y el manejador no se usa después.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{c_char, c_void, CStr};
use std::net::ToSocketAddrs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use armax_keys::address::{decode, encode};
use armax_keys::bip39::Mnemonic;
use armax_keys::ed25519::wipe;
use armax_keys::rng::fill_os_random;
use armax_keys::wallet::{SecretVault, VaultError, Wallet};
use armax_node::app::{App, AppConfig};
use armax_node::network::Network;
use armax_node::{hex, parse_amount, unhex};
use armax_thermal::{Sensors, ThermalConfig};

pub const ARMAX_OK: i32 = 0;
pub const ARMAX_ERR_ARG: i32 = -1;
pub const ARMAX_ERR_BUFFER: i32 = -2;
pub const ARMAX_ERR_VAULT: i32 = -3;
pub const ARMAX_ERR_WALLET: i32 = -4;
pub const ARMAX_ERR_NODE: i32 = -5;
pub const ARMAX_ERR_PANIC: i32 = -6;

const HANDLE_MAGIC: u64 = 0x41524D41_58484E44; // "ARMAXHND"

thread_local! {
    static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
}

fn set_err(msg: impl Into<String>) {
    LAST_ERROR.with(|e| *e.borrow_mut() = msg.into());
}

fn guard(f: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| {
        set_err("pánico interno");
        ARMAX_ERR_PANIC
    })
}

// ------------------------------------------------------------------ búferes y textos

unsafe fn write_cstr(out: *mut c_char, cap: usize, s: &str) -> i32 {
    if out.is_null() || cap < s.len() + 1 {
        set_err(format!("búfer pequeño: hacen falta {} bytes", s.len() + 1));
        return ARMAX_ERR_BUFFER;
    }
    std::ptr::copy_nonoverlapping(s.as_ptr(), out as *mut u8, s.len());
    *out.add(s.len()) = 0;
    s.len() as i32
}

unsafe fn write_bytes(out: *mut u8, cap: usize, len_out: *mut usize, data: &[u8]) -> i32 {
    if out.is_null() || len_out.is_null() || cap < data.len() {
        set_err(format!("búfer pequeño: hacen falta {} bytes", data.len()));
        return ARMAX_ERR_BUFFER;
    }
    std::ptr::copy_nonoverlapping(data.as_ptr(), out, data.len());
    *len_out = data.len();
    ARMAX_OK
}

unsafe fn cstr<'a>(p: *const c_char) -> Result<&'a str, i32> {
    if p.is_null() {
        set_err("puntero nulo");
        return Err(ARMAX_ERR_ARG);
    }
    CStr::from_ptr(p).to_str().map_err(|_| {
        set_err("texto no es UTF-8");
        ARMAX_ERR_ARG
    })
}

// ------------------------------------------------------------------ bóveda (Keystore)

/// Callback de la bóveda: lee `input`, escribe en `out` (capacidad `out_cap`) y deja en `*out_len`
/// los bytes escritos. Devuelve 0 si salió bien.
pub type VaultFn = extern "C" fn(
    ctx: *mut c_void,
    input: *const u8,
    input_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ArmaxVault {
    pub ctx: *mut c_void,
    pub seal: Option<VaultFn>,
    pub open: Option<VaultFn>,
}

struct CallbackVault(ArmaxVault);

fn call_vault(f: Option<VaultFn>, ctx: *mut c_void, input: &[u8], cap: usize) -> Result<Vec<u8>, VaultError> {
    let f = f.ok_or_else(|| VaultError::Unavailable("falta el callback de la bóveda".into()))?;
    let mut out = vec![0u8; cap];
    let mut n = 0usize;
    let rc = f(ctx, input.as_ptr(), input.len(), out.as_mut_ptr(), cap, &mut n);
    if rc != 0 {
        wipe(&mut out);
        return Err(VaultError::Unavailable(format!("el Keystore devolvió {rc}")));
    }
    if n > cap {
        wipe(&mut out);
        return Err(VaultError::Corrupt);
    }
    out.truncate(n);
    Ok(out)
}

impl SecretVault for CallbackVault {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
        // AES-GCM añade IV (12) y etiqueta (16): sobra con 256 bytes
        call_vault(self.0.seal, self.0.ctx, plaintext, plaintext.len() + 256)
    }
    fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, VaultError> {
        call_vault(self.0.open, self.0.ctx, sealed, sealed.len() + 16)
    }
}

unsafe fn vault_arg(p: *const ArmaxVault) -> Result<CallbackVault, i32> {
    if p.is_null() {
        set_err("bóveda nula");
        return Err(ARMAX_ERR_ARG);
    }
    Ok(CallbackVault(*p))
}

unsafe fn slice_arg<'a>(p: *const u8, len: usize) -> Result<&'a [u8], i32> {
    if p.is_null() && len > 0 {
        set_err("puntero nulo");
        return Err(ARMAX_ERR_ARG);
    }
    Ok(if len == 0 { &[] } else { std::slice::from_raw_parts(p, len) })
}

// ------------------------------------------------------------------ utilidades

/// Copia la versión de la biblioteca.
#[no_mangle]
pub unsafe extern "C" fn armax_version(out: *mut c_char, cap: usize) -> i32 {
    guard(|| write_cstr(out, cap, env!("CARGO_PKG_VERSION")))
}

/// Detalle del último error de este hilo.
#[no_mangle]
pub unsafe extern "C" fn armax_last_error(out: *mut c_char, cap: usize) -> i32 {
    guard(|| LAST_ERROR.with(|e| write_cstr(out, cap, &e.borrow())))
}

// ------------------------------------------------------------------ cartera

/// Crea una cartera nueva. Escribe la frase de respaldo (12 palabras) en `mnemonic_out`, que la
/// app muestra **una sola vez**, y el sellado en `sealed_out`, que la app guarda en disco.
#[no_mangle]
pub unsafe extern "C" fn armax_wallet_create(
    vault: *const ArmaxVault,
    mnemonic_out: *mut c_char,
    mnemonic_cap: usize,
    sealed_out: *mut u8,
    sealed_cap: usize,
    sealed_len: *mut usize,
) -> i32 {
    guard(|| {
        let v = match vault_arg(vault) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let mut entropy = [0u8; 16];
        if let Err(e) = fill_os_random(&mut entropy) {
            set_err(format!("sin aleatorio del sistema: {e}"));
            return ARMAX_ERR_WALLET;
        }
        let r = Wallet::create(v, &entropy);
        wipe(&mut entropy);
        match r {
            Ok((w, m)) => {
                let rc = write_cstr(mnemonic_out, mnemonic_cap, m.phrase());
                if rc < 0 {
                    return rc;
                }
                write_bytes(sealed_out, sealed_cap, sealed_len, w.sealed())
            }
            Err(e) => {
                set_err(format!("{e:?}"));
                ARMAX_ERR_VAULT
            }
        }
    })
}

/// Restaura una cartera desde su frase de respaldo (teléfono nuevo): devuelve el sellado nuevo.
#[no_mangle]
pub unsafe extern "C" fn armax_wallet_restore(
    vault: *const ArmaxVault,
    mnemonic: *const c_char,
    sealed_out: *mut u8,
    sealed_cap: usize,
    sealed_len: *mut usize,
) -> i32 {
    guard(|| {
        let v = match vault_arg(vault) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let phrase = match cstr(mnemonic) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let m = match Mnemonic::from_phrase(phrase) {
            Ok(m) => m,
            Err(e) => {
                set_err(format!("frase inválida: {e:?}"));
                return ARMAX_ERR_ARG;
            }
        };
        match Wallet::restore(v, &m) {
            Ok(w) => write_bytes(sealed_out, sealed_cap, sealed_len, w.sealed()),
            Err(e) => {
                set_err(format!("{e:?}"));
                ARMAX_ERR_VAULT
            }
        }
    })
}

/// Dirección de recepción (`arm1…`) de una cartera sellada.
#[no_mangle]
pub unsafe extern "C" fn armax_wallet_address(
    vault: *const ArmaxVault,
    sealed: *const u8,
    sealed_len: usize,
    out: *mut c_char,
    cap: usize,
) -> i32 {
    guard(|| {
        let v = match vault_arg(vault) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let sealed = match slice_arg(sealed, sealed_len) {
            Ok(s) => s.to_vec(),
            Err(e) => return e,
        };
        match Wallet::from_sealed(v, sealed).address("", 0, 0) {
            Ok(a) => write_cstr(out, cap, &encode(&a)),
            Err(e) => {
                set_err(format!("{e:?}"));
                ARMAX_ERR_VAULT
            }
        }
    })
}

// ------------------------------------------------------------------ configuración

#[derive(Debug, Clone, PartialEq)]
enum Val {
    Str(String),
    Num(f64),
    Bool(bool),
}

/// Lector de un objeto JSON plano (`{"clave": "texto" | número | true | false | null}`).
fn parse_flat_json(s: &str) -> Result<HashMap<String, Val>, String> {
    let c: Vec<char> = s.chars().collect();
    let mut i = 0usize;
    fn ws(c: &[char], i: &mut usize) {
        while *i < c.len() && c[*i].is_whitespace() {
            *i += 1;
        }
    }
    fn string(c: &[char], i: &mut usize) -> Result<String, String> {
        if c.get(*i) != Some(&'"') {
            return Err("se esperaba una cadena".into());
        }
        *i += 1;
        let mut out = String::new();
        while *i < c.len() {
            match c[*i] {
                '"' => {
                    *i += 1;
                    return Ok(out);
                }
                '\\' => {
                    *i += 1;
                    match c.get(*i) {
                        Some('"') => out.push('"'),
                        Some('\\') => out.push('\\'),
                        Some('/') => out.push('/'),
                        Some('n') => out.push('\n'),
                        Some('t') => out.push('\t'),
                        Some('r') => out.push('\r'),
                        _ => return Err("escape no soportado".into()),
                    }
                    *i += 1;
                }
                ch => {
                    out.push(ch);
                    *i += 1;
                }
            }
        }
        Err("cadena sin cerrar".into())
    }
    ws(&c, &mut i);
    if c.get(i) != Some(&'{') {
        return Err("se esperaba '{'".into());
    }
    i += 1;
    let mut map = HashMap::new();
    loop {
        ws(&c, &mut i);
        if c.get(i) == Some(&'}') {
            i += 1;
            break;
        }
        let key = string(&c, &mut i)?;
        ws(&c, &mut i);
        if c.get(i) != Some(&':') {
            return Err("se esperaba ':'".into());
        }
        i += 1;
        ws(&c, &mut i);
        let val = match c.get(i) {
            Some('"') => Some(Val::Str(string(&c, &mut i)?)),
            Some(_) => {
                let start = i;
                while i < c.len() && !matches!(c[i], ',' | '}') && !c[i].is_whitespace() {
                    i += 1;
                }
                let tok: String = c[start..i].iter().collect();
                match tok.as_str() {
                    "true" => Some(Val::Bool(true)),
                    "false" => Some(Val::Bool(false)),
                    "null" => None,
                    n => Some(Val::Num(n.parse::<f64>().map_err(|_| format!("valor inválido: {n}"))?)),
                }
            }
            None => return Err("JSON incompleto".into()),
        };
        if let Some(v) = val {
            map.insert(key, v);
        }
        ws(&c, &mut i);
        match c.get(i) {
            Some(',') => i += 1,
            Some('}') => {
                i += 1;
                break;
            }
            _ => return Err("se esperaba ',' o '}'".into()),
        }
    }
    ws(&c, &mut i);
    if i != c.len() {
        return Err("texto sobrante tras el objeto".into());
    }
    Ok(map)
}

fn get_str<'a>(m: &'a HashMap<String, Val>, k: &str) -> Option<&'a str> {
    match m.get(k) {
        Some(Val::Str(s)) => Some(s),
        _ => None,
    }
}
fn get_bool(m: &HashMap<String, Val>, k: &str, default: bool) -> bool {
    match m.get(k) {
        Some(Val::Bool(b)) => *b,
        _ => default,
    }
}
fn get_num(m: &HashMap<String, Val>, k: &str, default: f64) -> f64 {
    match m.get(k) {
        Some(Val::Num(n)) => *n,
        _ => default,
    }
}

// ------------------------------------------------------------------ nodo

struct Handle {
    magic: u64,
    app: App,
    sensors: Arc<Mutex<Sensors>>,
}

unsafe fn handle_ref<'a>(h: *mut c_void) -> Result<&'a mut Handle, i32> {
    if h.is_null() {
        set_err("manejador nulo");
        return Err(ARMAX_ERR_ARG);
    }
    let r = &mut *(h as *mut Handle);
    if r.magic != HANDLE_MAGIC {
        set_err("manejador inválido");
        return Err(ARMAX_ERR_ARG);
    }
    Ok(r)
}

/// Arranca el nodo.
///
/// `config_json` (objeto plano): `network` ("fast"|"devnet"|"testnet", obligatorio), `data_dir` (obligatorio),
/// `listen` ("IP:PUERTO", opcional), `connect` ("IP:PUERTO,IP:PUERTO"), `mine` (bool), `pool` (bool: participa en la sharechain/P2Pool),
/// `threads` (n), `use_governor` (bool, por defecto true), `any_power` (bool), `min_battery` (0-100, por defecto 15),
/// `pause_when_screen_on` (bool, por defecto true), `no_temp` (bool),
/// `trust_store` (bool), `pin` ("IP:PUERTO=CLAVE64HEX,…": claves públicas fijadas de los nodos a los
/// que se marca; el nodo imprime la suya al arrancar con `listen`).
///
/// Si `sealed_len > 0` se desbloquea la cartera con la bóveda (la dirección recibe las
/// recompensas y firma los envíos); si es 0, el nodo corre sin cartera (no puede minar ni enviar).
#[no_mangle]
pub unsafe extern "C" fn armax_node_start(
    config_json: *const c_char,
    vault: *const ArmaxVault,
    sealed: *const u8,
    sealed_len: usize,
    out_handle: *mut *mut c_void,
) -> i32 {
    guard(|| {
        if out_handle.is_null() {
            set_err("out_handle nulo");
            return ARMAX_ERR_ARG;
        }
        let json = match cstr(config_json) {
            Ok(j) => j,
            Err(e) => return e,
        };
        let m = match parse_flat_json(json) {
            Ok(m) => m,
            Err(e) => {
                set_err(format!("configuración inválida: {e}"));
                return ARMAX_ERR_ARG;
            }
        };
        let Some(network) = get_str(&m, "network").and_then(Network::parse) else {
            set_err("falta `network` (fast|devnet)");
            return ARMAX_ERR_ARG;
        };
        let Some(data_dir) = get_str(&m, "data_dir") else {
            set_err("falta `data_dir`");
            return ARMAX_ERR_ARG;
        };
        let resolve = |s: &str| -> Result<std::net::SocketAddr, String> {
            s.trim().to_socket_addrs().map_err(|e| format!("{s}: {e}"))?.next().ok_or_else(|| format!("{s}: sin dirección"))
        };
        let listen = match get_str(&m, "listen").filter(|s| !s.is_empty()).map(resolve).transpose() {
            Ok(l) => l,
            Err(e) => {
                set_err(e);
                return ARMAX_ERR_ARG;
            }
        };
        let connect: Result<Vec<_>, _> =
            get_str(&m, "connect").unwrap_or("").split(',').filter(|s| !s.trim().is_empty()).map(resolve).collect();
        let connect = match connect {
            Ok(c) => c,
            Err(e) => {
                set_err(e);
                return ARMAX_ERR_ARG;
            }
        };

        // claves fijadas: "IP:PUERTO=CLAVE64HEX,IP:PUERTO=CLAVE64HEX"
        let mut pins = Vec::new();
        for p in get_str(&m, "pin").unwrap_or("").split(',').filter(|s| !s.trim().is_empty()) {
            let parsed = p.split_once('=').and_then(|(a, k)| {
                let key: [u8; 32] = unhex(k.trim()).and_then(|v| v.try_into().ok())?;
                Some((resolve(a).ok()?, key))
            });
            match parsed {
                Some(x) => pins.push(x),
                None => {
                    set_err(format!("`pin` inválido: {p}"));
                    return ARMAX_ERR_ARG;
                }
            }
        }

        // cartera: se desbloquea ahora y solo viaja la semilla de la dirección 0
        let identity_seed = if sealed_len > 0 {
            let v = match vault_arg(vault) {
                Ok(v) => v,
                Err(e) => return e,
            };
            let sealed = match slice_arg(sealed, sealed_len) {
                Ok(s) => s.to_vec(),
                Err(e) => return e,
            };
            match Wallet::from_sealed(v, sealed).keypair("", 0, 0) {
                Ok(kp) => Some(kp.seed()),
                Err(e) => {
                    set_err(format!("no se pudo desbloquear la cartera: {e:?}"));
                    return ARMAX_ERR_VAULT;
                }
            }
        } else {
            None
        };

        let threads = get_num(&m, "threads", 1.0).clamp(1.0, 16.0) as usize;
        let mut thermal = ThermalConfig::default();
        thermal.require_charging = !get_bool(&m, "any_power", false);
        thermal.allow_without_temperature = get_bool(&m, "no_temp", false);
        // batería mínima (%) para minar sin cargador (solo con `any_power`)
        thermal.min_battery_pct_unplugged = get_num(&m, "min_battery", thermal.min_battery_pct_unplugged as f64).clamp(0.0, 100.0) as u8;
        // por defecto el gobernador pausa mientras la pantalla está encendida; con `false` mina igual
        thermal.pause_when_screen_on = get_bool(&m, "pause_when_screen_on", true);
        thermal.max_threads = threads as u8;
        if network == Network::Fast {
            thermal.mem_per_thread_mib = 1;
            thermal.mem_headroom_mib = 0;
        }
        let sensors = Arc::new(Mutex::new(Sensors::default()));
        let cfg = AppConfig {
            network,
            data_dir: PathBuf::from(data_dir),
            listen,
            connect,
            wallet: None,
            identity_seed,
            mine: get_bool(&m, "mine", false),
            pool: get_bool(&m, "pool", false),
            threads,
            use_governor: get_bool(&m, "use_governor", true),
            thermal,
            trust_store: get_bool(&m, "trust_store", false),
            sensors: Some(sensors.clone()),
            node_key: None,
            pins,
        };
        match App::start(cfg) {
            Ok(app) => {
                let h = Box::new(Handle { magic: HANDLE_MAGIC, app, sensors });
                *out_handle = Box::into_raw(h) as *mut c_void;
                ARMAX_OK
            }
            Err(e) => {
                set_err(e);
                ARMAX_ERR_NODE
            }
        }
    })
}

fn json_opt_num(v: Option<f64>) -> String {
    v.map_or("null".to_string(), |x| format!("{x:.1}"))
}
fn json_opt_str(v: Option<String>) -> String {
    v.map_or("null".to_string(), |x| format!("\"{x}\""))
}

/// Estado en JSON: `{"height","tip","peers","ready_peers","known_addrs","mempool","syncing",
/// "balance","spendable","address","network","miner":{…}|null}`. Los montos son cadenas con
/// unidades enteras (1 ARM = 100000000).
#[no_mangle]
pub unsafe extern "C" fn armax_node_status(handle: *mut c_void, out: *mut c_char, cap: usize) -> i32 {
    guard(|| {
        let h = match handle_ref(handle) {
            Ok(h) => h,
            Err(e) => return e,
        };
        let n = h.app.snapshot();
        let miner = match &n.miner {
            Some(m) => format!(
                "{{\"threads\":{},\"reason\":\"{}\",\"hashrate\":{:.2},\"blocks\":{},\"shares_found\":{},\"battery_temp_c\":{}}}",
                m.threads,
                m.reason.replace('"', ""),
                m.hashrate,
                m.blocks_found,
                m.shares_found,
                json_opt_num(m.battery_temp_c)
            ),
            None => "null".into(),
        };
        let pool = match &n.pool {
            Some(p) => format!(
                "{{\"shares\":{},\"orphans\":{},\"my_ppm\":{}}}",
                p.shares,
                p.orphans,
                p.my_ppm.map_or("null".to_string(), |v| v.to_string())
            ),
            None => "null".into(),
        };
        let s = format!(
            "{{\"height\":{},\"tip\":\"{}\",\"peers\":{},\"ready_peers\":{},\"known_addrs\":{},\"mempool\":{},\"syncing\":{},\"balance\":{},\"spendable\":{},\"address\":{},\"network\":\"{}\",\"miner\":{},\"pool\":{}}}",
            n.height,
            hex(&n.tip),
            n.peers,
            n.ready_peers,
            n.known_addrs,
            n.mempool,
            n.syncing,
            json_opt_str(n.balance.map(|b| b.to_string())),
            json_opt_str(n.spendable.map(|b| b.to_string())),
            json_opt_str(h.app.address_string()),
            h.app.network.name(),
            miner,
            pool
        );
        write_cstr(out, cap, &s)
    })
}

/// Historial de la cartera en JSON: arreglo de objetos, lo más reciente primero (primero lo
/// pendiente en el mempool). Cada uno: `{"kind":"mined"|"received"|"sent"|"internal",
/// "amount":"unidades","height":N|null,"timestamp":N|null,"txid":"64hex"|null,
/// "counterparty":"arm1…"|null,"confirmations":N,"matures_in":N}`. `limit` (1–500) acota la
/// cantidad. Un historial largo necesita un búfer grande (≈ 330 bytes por entrada).
#[no_mangle]
pub unsafe extern "C" fn armax_node_history(handle: *mut c_void, limit: u32, out: *mut c_char, cap: usize) -> i32 {
    guard(|| {
        let h = match handle_ref(handle) {
            Ok(h) => h,
            Err(e) => return e,
        };
        let limit = (limit as usize).clamp(1, 500);
        let entries = match h.app.history(limit) {
            Ok(e) => e,
            Err(e) => {
                set_err(e);
                return ARMAX_ERR_NODE;
            }
        };
        let num = |v: Option<u64>| v.map_or("null".to_string(), |x| x.to_string());
        let mut s = String::from("[");
        for (i, e) in entries.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&format!(
                "{{\"kind\":\"{}\",\"amount\":\"{}\",\"height\":{},\"timestamp\":{},\"txid\":{},\"counterparty\":{},\"confirmations\":{},\"matures_in\":{},\"fee\":{}}}",
                e.kind.name(),
                e.amount,
                num(e.height),
                num(e.timestamp),
                json_opt_str(e.txid.map(|t| hex(&t))),
                json_opt_str(e.counterparty.as_ref().map(encode)),
                e.confirmations,
                e.matures_in,
                e.fee.map_or("null".to_string(), |f| format!("\"{f}\""))
            ));
        }
        s.push(']');
        write_cstr(out, cap, &s)
    })
}

/// Envía `amount_units` a `to` (`arm1…`). `fee_units = 0` usa la comisión por defecto. Escribe
/// el id de la transacción (64 hex).
#[no_mangle]
pub unsafe extern "C" fn armax_node_send(
    handle: *mut c_void,
    to: *const c_char,
    amount_units: u64,
    fee_units: u64,
    out: *mut c_char,
    cap: usize,
) -> i32 {
    guard(|| {
        let h = match handle_ref(handle) {
            Ok(h) => h,
            Err(e) => return e,
        };
        let to = match cstr(to) {
            Ok(t) => t,
            Err(e) => return e,
        };
        if decode(to).is_err() {
            set_err("dirección inválida");
            return ARMAX_ERR_ARG;
        }
        match h.app.send(to, amount_units, if fee_units == 0 { None } else { Some(fee_units) }) {
            Ok(msg) => {
                let txid = msg.strip_prefix("enviada: ").unwrap_or(&msg).to_string();
                write_cstr(out, cap, &txid)
            }
            Err(e) => {
                set_err(e);
                ARMAX_ERR_NODE
            }
        }
    })
}

/// Convierte "12.5" en unidades (8 decimales máx.). Escribe el resultado en `*out_units`.
#[no_mangle]
pub unsafe extern "C" fn armax_parse_amount(text: *const c_char, out_units: *mut u64) -> i32 {
    guard(|| {
        if out_units.is_null() {
            set_err("puntero nulo");
            return ARMAX_ERR_ARG;
        }
        let t = match cstr(text) {
            Ok(t) => t,
            Err(e) => return e,
        };
        match parse_amount(t) {
            Ok(u) => {
                *out_units = u;
                ARMAX_OK
            }
            Err(e) => {
                set_err(e);
                ARMAX_ERR_ARG
            }
        }
    })
}

/// Empuja las lecturas del dispositivo al gobernador. `battery_temp_c`: NaN = desconocida.
/// `charging`, `screen_on`: -1 desconocido, 0 no, 1 sí. `battery_pct`, `mem_available_mib`: <0 = desconocido.
#[no_mangle]
pub unsafe extern "C" fn armax_node_push_sensors(
    handle: *mut c_void,
    battery_temp_c: f64,
    charging: i32,
    battery_pct: i32,
    screen_on: i32,
    mem_available_mib: i64,
) -> i32 {
    guard(|| {
        let h = match handle_ref(handle) {
            Ok(h) => h,
            Err(e) => return e,
        };
        let tri = |v: i32| match v {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        };
        let mut s = h.sensors.lock().unwrap();
        s.battery_temp_c = if battery_temp_c.is_finite() { Some(battery_temp_c) } else { None };
        s.charging = tri(charging);
        s.battery_pct = if (0..=100).contains(&battery_pct) { Some(battery_pct as u8) } else { None };
        s.screen_on = tri(screen_on);
        s.mem_available_mib = if mem_available_mib >= 0 { Some(mem_available_mib as u64) } else { None };
        ARMAX_OK
    })
}

/// Detiene el nodo y libera el manejador. No usar el manejador después.
#[no_mangle]
pub unsafe extern "C" fn armax_node_stop(handle: *mut c_void) -> i32 {
    guard(|| {
        if handle_ref(handle).is_err() {
            return ARMAX_ERR_ARG;
        }
        let mut h = Box::from_raw(handle as *mut Handle);
        h.magic = 0;
        h.app.shutdown();
        ARMAX_OK
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flat_json_parses_and_rejects() {
        let m = parse_flat_json(r#" { "network":"fast", "mine": true, "threads": 2, "x": null, "d":"a\\b\"c" } "#).unwrap();
        assert_eq!(get_str(&m, "network"), Some("fast"));
        assert!(get_bool(&m, "mine", false));
        assert_eq!(get_num(&m, "threads", 0.0), 2.0);
        assert_eq!(get_str(&m, "d"), Some("a\\b\"c"));
        assert!(!m.contains_key("x"));
        for bad in ["", "{", "[]", r#"{"a" 1}"#, r#"{"a":}"#, r#"{"a":1,}x"#, r#"{"a":"x\q"}"#, r#"{"a":1} basura"#] {
            assert!(parse_flat_json(bad).is_err(), "{bad:?}");
        }
        assert_eq!(parse_flat_json("{}").unwrap().len(), 0);
    }
}
