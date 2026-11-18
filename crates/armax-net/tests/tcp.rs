//! Prueba real con sockets TCP en el bucle local.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use armax_chain::block::genesis_block;
use armax_chain::{Address, DamperParams, SkipPow};
use armax_ledger::Ledger;
use armax_mempool::{Mempool, MempoolConfig};
use armax_net::codec::NetAddr;
use armax_net::node::{Node, NodeConfig};
use armax_net::tcp::{spawn, to_netaddr};

const T0: u64 = 1_800_000_000;

fn wall() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

/// El génesis y los timestamps deben ser anteriores al reloj real (el nodo rechaza el futuro).
fn base() -> u64 {
    // fijo durante toda la prueba: dos nodos creados con segundos de diferencia deben compartir génesis
    static BASE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *BASE.get_or_init(|| wall() - 1_000_000)
}

fn node(serve: bool, seeds: Vec<NetAddr>, nonce: u64, pre_mined: u64) -> Node {
    let t0 = base();
    let mut ledger = Ledger::new(DamperParams::MAINNET, genesis_block(t0, b"tcp"), 1).unwrap();
    for h in 1..=pre_mined {
        let fb = ledger.build_template(&[(Address([1; 32]), 1_000_000)], t0 + h * 300, vec![], &[]).unwrap();
        ledger.add_block(fb, wall(), &mut SkipPow).unwrap();
    }
    let cfg = NodeConfig { serve, seeds, headers_per_step: 1_000, ..NodeConfig::default() };
    Node::new(ledger, Mempool::new(MempoolConfig::default()), None, Box::new(SkipPow), cfg, nonce)
}

fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(20) {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("tiempo agotado esperando: {what}");
}

#[test]
fn two_nodes_sync_and_relay_over_real_sockets() {
    let _ = T0;
    let server = spawn(node(true, vec![], 1, 40), Some("127.0.0.1:0".parse::<SocketAddr>().unwrap())).unwrap();
    let saddr = server.local_addr.unwrap();
    let phone = spawn(node(false, vec![to_netaddr(saddr)], 2, 0), None).unwrap();

    // el teléfono marca a la semilla (en su primer tick) y descarga la cadena
    wait_until("descarga inicial", || phone.query(|n| n.ledger().tip_height()).unwrap() == 40);
    assert_eq!(
        phone.query(|n| n.ledger().tip_id()).unwrap(),
        server.query(|n| n.ledger().tip_id()).unwrap()
    );
    assert_eq!(server.query(|n| n.peer_count()).unwrap(), 1);

    // un bloque nuevo minado en el servidor llega al teléfono por el anuncio
    let t0 = base();
    let fb = server
        .query(move |n| n.ledger_mut().build_template(&[(Address([2; 32]), 1_000_000)], t0 + 41 * 300, vec![], &[]).unwrap())
        .unwrap();
    assert!(server.submit_block(fb).unwrap().is_ok());
    wait_until("bloque nuevo", || phone.query(|n| n.ledger().tip_height()).unwrap() == 41);

    // y al revés: el teléfono mina y el servidor lo recibe
    let fb = phone
        .query(move |n| n.ledger_mut().build_template(&[(Address([3; 32]), 1_000_000)], t0 + 42 * 300, vec![], &[]).unwrap())
        .unwrap();
    assert!(phone.submit_block(fb).unwrap().is_ok());
    wait_until("bloque del teléfono", || server.query(|n| n.ledger().tip_height()).unwrap() == 42);

    phone.shutdown();
    server.shutdown();
}

/// Un cliente sin cifrado (el protocolo anterior) es expulsado y no cuenta como par.
#[test]
fn a_plaintext_client_is_dropped() {
    use armax_net::codec::Message;
    use std::io::{Read, Write};
    let server = spawn(node(true, vec![], 1, 3), Some("127.0.0.1:0".parse::<SocketAddr>().unwrap())).unwrap();
    let mut raw = std::net::TcpStream::connect(server.local_addr.unwrap()).unwrap();
    raw.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let _ = raw.write_all(&Message::Ping(7).encode());
    let _ = raw.write_all(&[0u8; 64]);
    let mut buf = [0u8; 64];
    // el servidor responde con su clave efímera (32 bytes) y luego cierra; nunca habla en claro
    let mut total = 0;
    loop {
        match raw.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => total += n,
        }
        assert!(total <= 32 + 64, "habló de más con un cliente sin cifrado");
    }
    assert_eq!(server.query(|n| n.peer_count()).unwrap(), 0);
}

/// Un espía entre el teléfono y el servidor ve la sincronización completa pero no puede leer nada:
/// el hash del bloque 39 va dentro de la cabecera del bloque 40 y no debe aparecer en la red.
#[test]
fn an_eavesdropper_sees_no_plaintext() {
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};
    let server = spawn(node(true, vec![], 1, 40), Some("127.0.0.1:0".parse::<SocketAddr>().unwrap())).unwrap();
    let saddr = server.local_addr.unwrap();
    let seen: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(vec![]));

    let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let paddr = proxy.local_addr().unwrap();
    let seen2 = seen.clone();
    std::thread::spawn(move || {
        let (client, _) = proxy.accept().unwrap();
        let upstream = std::net::TcpStream::connect(saddr).unwrap();
        for (mut from, mut to) in [
            (client.try_clone().unwrap(), upstream.try_clone().unwrap()),
            (upstream.try_clone().unwrap(), client.try_clone().unwrap()),
        ] {
            let seen = seen2.clone();
            std::thread::spawn(move || {
                let mut b = [0u8; 4096];
                while let Ok(n) = from.read(&mut b) {
                    if n == 0 || to.write_all(&b[..n]).is_err() {
                        break;
                    }
                    seen.lock().unwrap().extend_from_slice(&b[..n]);
                }
            });
        }
    });

    let phone = spawn(node(false, vec![to_netaddr(paddr)], 2, 0), None).unwrap();
    wait_until("descarga inicial por el proxy", || phone.query(|n| n.ledger().tip_height()).unwrap() == 40);
    let id39 = server.query(|n| n.ledger().chain().id_at_height(39).unwrap()).unwrap();
    let wire = seen.lock().unwrap().clone();
    assert!(wire.len() > 10_000, "el proxy debió ver la sincronización ({} bytes)", wire.len());
    assert!(!wire.windows(32).any(|w| w == id39), "el id de un bloque viajó en claro");
}

/// Con la clave del servidor fijada el teléfono sincroniza; con otra clave (un impostor) no.
#[test]
fn pinned_server_key_is_enforced() {
    use armax_keys::x25519::public_key;
    use armax_net::tcp::{spawn_with, TcpOptions};
    let secret = [0x77u8; 32];
    let server = spawn_with(
        node(true, vec![], 1, 20),
        Some("127.0.0.1:0".parse::<SocketAddr>().unwrap()),
        TcpOptions { identity: Some(secret), ..Default::default() },
    )
    .unwrap();
    let saddr = server.local_addr.unwrap();

    // clave equivocada: nunca se conecta ni sincroniza
    let wrong = spawn_with(
        node(false, vec![to_netaddr(saddr)], 2, 0),
        None,
        TcpOptions { pins: [(saddr, public_key(&[0x78u8; 32]))].into_iter().collect(), ..Default::default() },
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(2500));
    assert_eq!(wrong.query(|n| n.ledger().tip_height()).unwrap(), 0);
    assert_eq!(wrong.query(|n| n.peer_count()).unwrap(), 0);
    assert_eq!(server.query(|n| n.peer_count()).unwrap(), 0);

    // clave correcta: sincroniza
    let right = spawn_with(
        node(false, vec![to_netaddr(saddr)], 3, 0),
        None,
        TcpOptions { pins: [(saddr, public_key(&secret))].into_iter().collect(), ..Default::default() },
    )
    .unwrap();
    wait_until("descarga con clave fijada", || right.query(|n| n.ledger().tip_height()).unwrap() == 20);
}
