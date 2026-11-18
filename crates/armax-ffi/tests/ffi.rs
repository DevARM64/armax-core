//! Prueba de extremo a extremo de la interfaz C, llamándola como lo haría Kotlin.
//! La "bóveda" es un callback de Rust (XOR + etiqueta) que imita al Keystore.

use armax_ffi::*;
use std::ffi::{c_char, c_void, CStr, CString};
use std::time::{Duration, Instant};

const KEY: u8 = 0x5A;

extern "C" fn v_seal(_c: *mut c_void, i: *const u8, il: usize, o: *mut u8, cap: usize, ol: *mut usize) -> i32 {
    unsafe {
        let inp = std::slice::from_raw_parts(i, il);
        if cap < il + 1 {
            return 7;
        }
        for (k, b) in inp.iter().enumerate() {
            *o.add(k) = b ^ KEY;
        }
        *o.add(il) = 0xEE; // etiqueta
        *ol = il + 1;
    }
    0
}
extern "C" fn v_open(_c: *mut c_void, i: *const u8, il: usize, o: *mut u8, _cap: usize, ol: *mut usize) -> i32 {
    unsafe {
        let inp = std::slice::from_raw_parts(i, il);
        if il == 0 || inp[il - 1] != 0xEE {
            return 9;
        }
        for k in 0..il - 1 {
            *o.add(k) = inp[k] ^ KEY;
        }
        *ol = il - 1;
    }
    0
}

fn vault() -> ArmaxVault {
    ArmaxVault { ctx: std::ptr::null_mut(), seal: Some(v_seal), open: Some(v_open) }
}

fn text(buf: &[u8]) -> String {
    CStr::from_bytes_until_nul(buf).unwrap().to_str().unwrap().to_string()
}

fn last_error() -> String {
    let mut b = vec![0u8; 512];
    unsafe { armax_last_error(b.as_mut_ptr() as *mut c_char, b.len()) };
    text(&b)
}

fn create_wallet() -> (String, Vec<u8>, String) {
    let v = vault();
    let mut mn = vec![0u8; 256];
    let mut sealed = vec![0u8; 256];
    let mut n = 0usize;
    let rc = unsafe { armax_wallet_create(&v, mn.as_mut_ptr() as *mut c_char, mn.len(), sealed.as_mut_ptr(), sealed.len(), &mut n) };
    assert_eq!(rc, 0, "{}", last_error());
    sealed.truncate(n);
    let mut addr = vec![0u8; 128];
    let rc = unsafe { armax_wallet_address(&v, sealed.as_ptr(), sealed.len(), addr.as_mut_ptr() as *mut c_char, addr.len()) };
    assert!(rc > 0, "{}", last_error());
    (text(&mn), sealed, text(&addr))
}

fn status(h: *mut c_void) -> String {
    let mut b = vec![0u8; 2048];
    let rc = unsafe { armax_node_status(h, b.as_mut_ptr() as *mut c_char, b.len()) };
    assert!(rc > 0, "{}", last_error());
    text(&b)
}

fn height_of(s: &str) -> u64 {
    let i = s.find("\"height\":").unwrap() + 9;
    s[i..].split(',').next().unwrap().parse().unwrap()
}

#[test]
fn wallet_roundtrip_and_errors() {
    let (phrase, sealed, addr) = create_wallet();
    assert_eq!(phrase.split_whitespace().count(), 12);
    assert!(addr.starts_with("arm"), "{addr}");

    // restaurar con la frase da la misma dirección
    let v = vault();
    let c = CString::new(phrase).unwrap();
    let mut s2 = vec![0u8; 256];
    let mut n = 0usize;
    assert_eq!(unsafe { armax_wallet_restore(&v, c.as_ptr(), s2.as_mut_ptr(), s2.len(), &mut n) }, 0, "{}", last_error());
    let mut a2 = vec![0u8; 128];
    assert!(unsafe { armax_wallet_address(&v, s2.as_ptr(), n, a2.as_mut_ptr() as *mut c_char, a2.len()) } > 0);
    assert_eq!(text(&a2), addr);

    // errores controlados
    let bad = CString::new("esto no es una frase").unwrap();
    assert_eq!(unsafe { armax_wallet_restore(&v, bad.as_ptr(), s2.as_mut_ptr(), s2.len(), &mut n) }, ARMAX_ERR_ARG);
    let mut small = [0u8; 4];
    assert_eq!(
        unsafe { armax_wallet_address(&v, sealed.as_ptr(), sealed.len(), small.as_mut_ptr() as *mut c_char, small.len()) },
        ARMAX_ERR_BUFFER
    );
    let mut corrupt = sealed.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    let mut out = vec![0u8; 128];
    assert_eq!(
        unsafe { armax_wallet_address(&v, corrupt.as_ptr(), corrupt.len(), out.as_mut_ptr() as *mut c_char, out.len()) },
        ARMAX_ERR_VAULT
    );
    assert_eq!(unsafe { armax_node_status(std::ptr::null_mut(), out.as_mut_ptr() as *mut c_char, out.len()) }, ARMAX_ERR_ARG);
    let none = ArmaxVault { ctx: std::ptr::null_mut(), seal: None, open: None };
    assert_eq!(
        unsafe { armax_wallet_address(&none, sealed.as_ptr(), sealed.len(), out.as_mut_ptr() as *mut c_char, out.len()) },
        ARMAX_ERR_VAULT
    );
}

#[test]
fn amounts_and_version() {
    let mut u = 0u64;
    let t = CString::new("12.5").unwrap();
    assert_eq!(unsafe { armax_parse_amount(t.as_ptr(), &mut u) }, 0);
    assert_eq!(u, 1_250_000_000);
    let t = CString::new("1.123456789").unwrap();
    assert_eq!(unsafe { armax_parse_amount(t.as_ptr(), &mut u) }, ARMAX_ERR_ARG);
    let mut v = [0u8; 16];
    assert!(unsafe { armax_version(v.as_mut_ptr() as *mut c_char, v.len()) } > 0);
}

#[test]
fn node_mines_and_pays_through_the_c_abi() {
    let dir = std::env::temp_dir().join(format!("armax-ffi-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (_p, sealed, addr) = create_wallet();
    let v = vault();

    let cfg = CString::new(format!(
        r#"{{"network":"fast","data_dir":"{}","mine":true,"threads":1,"any_power":false,"no_temp":false,"use_governor":true}}"#,
        dir.display()
    ))
    .unwrap();
    let mut h: *mut c_void = std::ptr::null_mut();
    let rc = unsafe { armax_node_start(cfg.as_ptr(), &v, sealed.as_ptr(), sealed.len(), &mut h) };
    assert_eq!(rc, 0, "{}", last_error());

    // sin sensores el gobernador falla seguro: no hay minado todavía
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(height_of(&status(h)), 0, "minó sin sensores");

    // el teléfono "empieza a cargar a 30 °C"
    assert_eq!(unsafe { armax_node_push_sensors(h, 30.0, 1, 80, 0, 4096) }, 0);
    let t0 = Instant::now();
    loop {
        let s = status(h);
        assert!(s.contains(&addr), "{s}");
        if height_of(&s) >= 6 {
            break;
        }
        assert!(t0.elapsed() < Duration::from_secs(120), "no minó: {s}");
        // refrescar sensores como haría el servicio de Android
        unsafe { armax_node_push_sensors(h, 30.0, 1, 80, 0, 4096) };
        std::thread::sleep(Duration::from_millis(500));
    }

    // pago a otra cartera
    let (_p2, _s2, dest) = create_wallet();
    let to = CString::new(dest).unwrap();
    let mut txid = vec![0u8; 128];
    let rc = unsafe { armax_node_send(h, to.as_ptr(), 500_000_000, 0, txid.as_mut_ptr() as *mut c_char, txid.len()) };
    assert_eq!(rc, 64, "{}", last_error());
    let bad = CString::new("arm1nope").unwrap();
    assert_eq!(
        unsafe { armax_node_send(h, bad.as_ptr(), 1, 0, txid.as_mut_ptr() as *mut c_char, txid.len()) },
        ARMAX_ERR_ARG
    );

    // historial en JSON: lo minado y el envío (pendiente o ya confirmado)
    let mut hb = vec![0u8; 65536];
    let n = unsafe { armax_node_history(h, 50, hb.as_mut_ptr() as *mut c_char, hb.len()) };
    assert!(n > 2, "{}", last_error());
    let hist = String::from_utf8(hb[..n as usize].to_vec()).unwrap();
    assert!(hist.starts_with('[') && hist.ends_with(']'), "{hist}");
    assert!(hist.contains("\"kind\":\"mined\"") && hist.contains("\"kind\":\"sent\""), "{hist}");
    assert!(hist.contains("\"amount\":\"500000000\""), "{hist}");
    // el envío trae su comisión (de sent.log); lo minado, null
    assert!(hist.contains("\"fee\":\""), "{hist}");
    assert!(hist.contains("\"fee\":null"), "{hist}");
    // búfer demasiado pequeño: error de búfer, no corrupción
    let mut tiny = [0u8; 8];
    assert_eq!(unsafe { armax_node_history(h, 50, tiny.as_mut_ptr() as *mut c_char, tiny.len()) }, ARMAX_ERR_BUFFER);

    assert_eq!(unsafe { armax_node_stop(h) }, 0);

    // reinicio: la cadena persiste
    let mut h2: *mut c_void = std::ptr::null_mut();
    assert_eq!(unsafe { armax_node_start(cfg.as_ptr(), &v, sealed.as_ptr(), sealed.len(), &mut h2) }, 0, "{}", last_error());
    assert!(height_of(&status(h2)) >= 6);
    assert_eq!(unsafe { armax_node_stop(h2) }, 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bad_config_is_rejected() {
    let mut h: *mut c_void = std::ptr::null_mut();
    for cfg in [r#"{"data_dir":"/tmp/x"}"#, r#"{"network":"fast"}"#, r#"{"network":"mainnet","data_dir":"/tmp/x"}"#, "no es json"] {
        let c = CString::new(cfg).unwrap();
        assert_eq!(unsafe { armax_node_start(c.as_ptr(), std::ptr::null(), std::ptr::null(), 0, &mut h) }, ARMAX_ERR_ARG, "{cfg}");
    }
    assert!(h.is_null());
}
