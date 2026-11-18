use std::path::PathBuf;
use std::time::{Duration, Instant};

use armax_chain::block::genesis_block;
use armax_chain::{Address, DamperParams, SkipPow, COIN};
use armax_keys::address::{decode, encode};
use armax_ledger::Ledger;
use armax_mempool::{Mempool, MempoolConfig};
use armax_node::app::{App, AppConfig};
use armax_node::network::{Network, DEVNET_GENESIS_TIME};
use armax_node::pay::{build_payment, spendable};
use armax_node::walletfile::WalletFile;
use armax_thermal::ThermalConfig;

struct TmpDir(PathBuf);
impl TmpDir {
    fn new(name: &str) -> TmpDir {
        let p = std::env::temp_dir().join(format!("armax-node-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TmpDir(p)
    }
}
impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn wait_until(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(secs) {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("tiempo agotado esperando: {what}");
}

#[test]
fn wallet_file_roundtrip_and_permissions() {
    let d = TmpDir::new("wallet");
    let p = d.0.join("w.txt");
    let (w, phrase) = WalletFile::create(&p).unwrap();
    assert_eq!(phrase.split_whitespace().count(), 12);
    let again = WalletFile::open(&p).unwrap();
    assert_eq!(w.address().unwrap(), again.address().unwrap());
    assert!(WalletFile::create(&p).is_err(), "no se sobrescribe");
    let a = encode(&w.address().unwrap());
    assert!(a.starts_with("arm1"));
    assert_eq!(decode(&a).unwrap(), w.address().unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
    }
    std::fs::write(&p, "basura").unwrap();
    assert!(WalletFile::open(&p).is_err());
}

#[test]
fn payments_pick_mature_free_coins_and_reject_overspending() {
    let d = TmpDir::new("pay");
    let (w, _) = WalletFile::create(&d.0.join("w")).unwrap();
    let (me, key) = (w.address().unwrap(), w.keypair().unwrap());
    let other = Address([9; 32]);
    let mut l = Ledger::new(DamperParams::MAINNET, genesis_block(DEVNET_GENESIS_TIME, b"pay"), 1).unwrap();
    let now = DEVNET_GENESIS_TIME + 10_000_000;
    for h in 1..=105u64 {
        let fb = l.build_template(&[(me, 1_000_000)], DEVNET_GENESIS_TIME + h * 300, vec![], &[]).unwrap();
        l.add_block(fb, now, &mut SkipPow).unwrap();
    }
    let mut pool = Mempool::new(MempoolConfig::default());
    // 105 bloques: el siguiente es el 106; maduran los de altura ≤ 6
    assert_eq!(spendable(&l, &pool, &me), 6 * 25 * COIN as u128);

    // 40 ARM necesitan 2 monedas de 25
    let tx = build_payment(&l, &pool, &key, &me, other, 40 * COIN, None).unwrap();
    assert_eq!(tx.inputs.len(), 2);
    assert_eq!(tx.outputs[0].amount, 40 * COIN);
    assert_eq!(tx.outputs.len(), 2, "con cambio");
    pool.add(tx, &l).unwrap();
    // esas 2 monedas ya están comprometidas; quedan 4 libres = 100 ARM
    assert_eq!(spendable(&l, &pool, &me), 4 * 25 * COIN as u128);
    // gastar más de lo libre falla con un mensaje claro
    let err = build_payment(&l, &pool, &key, &me, other, 101 * COIN, None).unwrap_err();
    assert!(err.contains("insuficiente"), "{err}");
    assert!(build_payment(&l, &pool, &key, &me, other, 0, None).is_err());
    // y el pago exacto con comisión explícita funciona
    let tx2 = build_payment(&l, &pool, &key, &me, other, 100 * COIN - 10_000, Some(10_000)).unwrap();
    assert_eq!(tx2.inputs.len(), 4);
    assert_eq!(tx2.outputs.len(), 1, "sin cambio");
    pool.add(tx2, &l).unwrap();
}

fn cfg(net: Network, dir: &TmpDir, name: &str, wallet: Option<PathBuf>, listen: bool, connect: Vec<std::net::SocketAddr>, mine: bool) -> AppConfig {
    let mut thermal = ThermalConfig::default();
    thermal.mem_per_thread_mib = 1;
    thermal.mem_headroom_mib = 0;
    AppConfig {
        network: net,
        data_dir: dir.0.join(name),
        listen: if listen { Some("127.0.0.1:0".parse().unwrap()) } else { None },
        connect,
        wallet,
        identity_seed: None,
        mine,
        pool: false,
        threads: 2,
        use_governor: false,
        thermal,
        trust_store: false,
        sensors: None,
        node_key: None,
        pins: vec![],
    }
}

#[test]
fn two_nodes_mine_sync_and_survive_a_restart() {
    let d = TmpDir::new("e2e");
    let wpath = d.0.join("miner.wallet");
    let (w, _) = WalletFile::create(&wpath).unwrap();
    let miner_addr = w.address().unwrap();

    // A: sirve y mina con PoW real (parámetros reducidos de la red `fast`)
    let a = App::start(cfg(Network::Fast, &d, "a", Some(wpath.clone()), true, vec![], true)).unwrap();
    let a_addr = a.handle.local_addr.unwrap();
    // B: teléfono, solo marca a A
    let b = App::start(cfg(Network::Fast, &d, "b", None, false, vec![a_addr], false)).unwrap();

    wait_until("3 bloques en ambos nodos", 120, || {
        a.handle.query(|n| n.ledger().tip_height()).unwrap() >= 3 && b.handle.query(|n| n.ledger().tip_height()).unwrap() >= 3
    });
    let tip_b = b.handle.query(|n| n.ledger().tip_id()).unwrap();
    assert!(a.handle.query(move |n| n.ledger().chain().contains(&tip_b)).unwrap(), "misma cadena");
    // la cadena es válida y el minero cobró
    let bal = a.handle.query(move |n| n.ledger().balance_of(&miner_addr)).unwrap();
    assert!(bal >= 3 * 25 * COIN as u128 / 2, "{bal}");
    let (u, e) = a.handle.query(|n| n.ledger().supply()).unwrap();
    assert_eq!(u as i128, e);
    assert!(a.status().contains("minando"));
    let height_a = a.handle.query(|n| n.ledger().tip_height()).unwrap();

    b.shutdown();
    a.shutdown();

    // reinicio de A (sin minar): reconstruye desde disco, re-verificando el PoW
    let a2 = App::start(cfg(Network::Fast, &d, "a", Some(wpath), false, vec![], false)).unwrap();
    let h = a2.handle.query(|n| n.ledger().tip_height()).unwrap();
    assert!(h >= height_a, "{h} < {height_a}");
    a2.shutdown();
}

#[test]
fn mining_without_a_wallet_is_refused() {
    let d = TmpDir::new("nowallet");
    let r = App::start(cfg(Network::Fast, &d, "x", None, false, vec![], true));
    assert!(r.is_err());
}

#[test]
fn a_payment_travels_from_a_miner_to_another_node_and_is_confirmed() {
    let d = TmpDir::new("send");
    let (wa, wb) = (d.0.join("a.wallet"), d.0.join("b.wallet"));
    WalletFile::create(&wa).unwrap();
    let (b_wallet, _) = WalletFile::create(&wb).unwrap();
    let b_addr = b_wallet.address().unwrap();
    let a = App::start(cfg(Network::Fast, &d, "a", Some(wa), true, vec![], true)).unwrap();
    let a_listen = a.handle.local_addr.unwrap();
    // B también mina (hacia su cartera) y está conectado a A
    let b = App::start(cfg(Network::Fast, &d, "b", Some(wb), false, vec![a_listen], false)).unwrap();

    // A espera a tener monedas maduras (la red fast madura a los 3 bloques)
    wait_until("saldo gastable en A", 120, || a.balance().map_or(false, |s| !s.contains("gastable ahora: 0.00000000")));
    let r = a.send(&encode(&b_addr), 7 * COIN + 5, None).unwrap();
    assert!(r.starts_with("enviada"), "{r}");
    // B la ve llegar al mempool o confirmada, y acaba con saldo
    wait_until("saldo en B", 120, || b.handle.query(move |n| n.ledger().balance_of(&b_addr)).unwrap() == (7 * COIN + 5) as u128);
    let (u, e) = b.handle.query(|n| n.ledger().supply()).unwrap();
    assert_eq!(u as i128, e);
    // doble envío con saldo insuficiente se rechaza con mensaje claro
    let err = a.send(&encode(&b_addr), 1_000_000 * COIN, None).unwrap_err();
    assert!(err.contains("insuficiente"), "{err}");
    b.shutdown();
    a.shutdown();
}

fn cfg_pool(net: Network, dir: &TmpDir, name: &str, wallet: Option<PathBuf>, listen: bool, connect: Vec<std::net::SocketAddr>, mine: bool) -> AppConfig {
    AppConfig { pool: true, ..cfg(net, dir, name, wallet, listen, connect, mine) }
}

#[test]
fn two_pool_miners_share_the_reward_of_the_blocks_they_find() {
    let d = TmpDir::new("pool");
    let (wa, wb) = (d.0.join("a.wallet"), d.0.join("b.wallet"));
    let (a_wallet, _) = WalletFile::create(&wa).unwrap();
    let (b_wallet, _) = WalletFile::create(&wb).unwrap();
    let (a_addr, b_addr) = (a_wallet.address().unwrap(), b_wallet.address().unwrap());
    let a = App::start(cfg_pool(Network::Fast, &d, "a", Some(wa), true, vec![], true)).unwrap();
    let a_listen = a.handle.local_addr.unwrap();
    let b = App::start(cfg_pool(Network::Fast, &d, "b", Some(wb), false, vec![a_listen], true)).unwrap();

    // los dos acaban con shares de ambos en su sharechain y algún bloque con coinbase repartido
    wait_until("shares de los dos mineros en A", 180, || {
        a.handle
            .query(move |n| {
                let sc = n.sharechain().unwrap();
                sc.len() >= 12 && sc.miner_ppm(&a_addr) > 0 && sc.miner_ppm(&b_addr) > 0
            })
            .unwrap()
    });
    wait_until("un bloque con dos pagos en ambos nodos", 180, || {
        [&a, &b].iter().all(|app| {
            app.handle
                .query(|n| {
                    let c = n.ledger().chain();
                    c.main_ids().iter().any(|id| n.ledger().full_block(id).map_or(false, |fb| fb.block.coinbase.outputs.len() >= 2))
                })
                .unwrap()
        })
    });
    // ambos pagan al otro: las dos carteras cobraron recompensa
    wait_until("saldo en las dos carteras", 180, || {
        a.handle.query(move |n| n.ledger().balance_of(&a_addr)).unwrap() > 0
            && a.handle.query(move |n| n.ledger().balance_of(&b_addr)).unwrap() > 0
    });
    let (u, e) = a.handle.query(|n| n.ledger().supply()).unwrap();
    assert_eq!(u as i128, e);
    let st = a.status();
    assert!(st.contains("pool:") && st.contains("tu parte"), "{st}");
    assert!(a.snapshot().miner.unwrap().shares_found > 0);
    b.shutdown();
    a.shutdown();
}

#[test]
fn a_pool_node_that_joins_late_downloads_the_whole_sharechain() {
    let d = TmpDir::new("poollate");
    let (wa, wb) = (d.0.join("a.wallet"), d.0.join("b.wallet"));
    WalletFile::create(&wa).unwrap();
    let (b_wallet, _) = WalletFile::create(&wb).unwrap();
    let b_addr = b_wallet.address().unwrap();
    let a = App::start(cfg_pool(Network::Fast, &d, "a", Some(wa), true, vec![], true)).unwrap();
    let a_listen = a.handle.local_addr.unwrap();
    // B llega con la sharechain de A ya en marcha y tiene que pedirla hacia atrás (el caso con más
    // shares que el tope de huérfanos lo cubre la simulación de armax-net)
    wait_until("40 shares en A", 240, || a.handle.query(|n| n.sharechain().unwrap().len()).unwrap() >= 40);
    let b = App::start(cfg_pool(Network::Fast, &d, "b", Some(wb), false, vec![a_listen], true)).unwrap();
    wait_until("B tiene la sharechain de A", 180, || {
        let (la, lb) = (
            a.handle.query(|n| n.sharechain().unwrap().len()).unwrap(),
            b.handle.query(|n| n.sharechain().unwrap().len()).unwrap(),
        );
        lb + 10 >= la && lb >= 40 && b.handle.query(|n| n.share_orphan_count()).unwrap() < 10
    });
    // y B ya aporta: su dirección entra en el reparto
    wait_until("B entra en el reparto", 180, || a.handle.query(move |n| n.sharechain().unwrap().miner_ppm(&b_addr)).unwrap() > 0);
    b.shutdown();
    a.shutdown();
}

#[test]
fn a_pool_node_keeps_its_sharechain_across_a_restart() {
    let d = TmpDir::new("poolrestart");
    let wa = d.0.join("a.wallet");
    WalletFile::create(&wa).unwrap();
    let a = App::start(cfg_pool(Network::Fast, &d, "a", Some(wa.clone()), false, vec![], true)).unwrap();
    wait_until("15 shares en A", 240, || a.handle.query(|n| n.sharechain().unwrap().len()).unwrap() >= 15);
    let (len, tip) = a.handle.query(|n| (n.sharechain().unwrap().len(), n.sharechain().unwrap().tip().unwrap())).unwrap();
    a.shutdown();
    assert!(d.0.join("a").join("shares.db").exists());

    // reinicio sin minar y sin pares: lo único que puede dar shares es el disco
    let a2 = App::start(cfg_pool(Network::Fast, &d, "a", Some(wa), false, vec![], false)).unwrap();
    let (len2, has_tip) = a2.handle.query(move |n| (n.sharechain().unwrap().len(), n.sharechain().unwrap().contains(&tip))).unwrap();
    assert!(len2 >= len, "{len2} < {len}");
    assert!(has_tip, "la punta de antes debe estar en la sharechain recuperada");
    a2.shutdown();
}

#[test]
fn a_pool_miner_puts_mempool_transactions_in_its_shares_and_the_fee_reaches_the_block() {
    let d = TmpDir::new("pooltx");
    let (wa, wb) = (d.0.join("a.wallet"), d.0.join("b.wallet"));
    WalletFile::create(&wa).unwrap();
    let (b_wallet, _) = WalletFile::create(&wb).unwrap();
    let b_addr = b_wallet.address().unwrap();
    let a = App::start(cfg_pool(Network::Fast, &d, "a", Some(wa), false, vec![], true)).unwrap();

    wait_until("saldo gastable en A", 240, || a.balance().map_or(false, |s| !s.contains("gastable ahora: 0.00000000")));
    let fee = 12_345u64;
    let r = a.send(&encode(&b_addr), 3 * COIN, Some(fee)).unwrap();
    assert!(r.starts_with("enviada"), "{r}");
    // todos los bloques salen de shares en modo pool: la transacción entra en uno con su comisión
    wait_until("la transacción confirmada en un bloque del pool", 240, || {
        a.handle.query(move |n| n.ledger().balance_of(&b_addr)).unwrap() == (3 * COIN) as u128
    });
    let (txs_in_blocks, fees_in_blocks) = a
        .handle
        .query(|n| {
            let c = n.ledger().chain();
            let mut t = 0;
            let mut f = 0;
            for id in c.main_ids() {
                if let Some(fb) = n.ledger().full_block(&id) {
                    t += fb.txs.len();
                    f += fb.block.coinbase.fees;
                }
            }
            (t, f)
        })
        .unwrap();
    assert_eq!(txs_in_blocks, 1);
    assert_eq!(fees_in_blocks, fee);
    let (u, e) = a.handle.query(|n| n.ledger().supply()).unwrap();
    assert_eq!(u as i128, e);
    a.shutdown();
}

#[test]
fn the_history_shows_what_was_mined_sent_and_received() {
    use armax_node::history::Kind;
    let d = TmpDir::new("history");
    let (wa, wb) = (d.0.join("a.wallet"), d.0.join("b.wallet"));
    let (a_wallet, _) = WalletFile::create(&wa).unwrap();
    let (b_wallet, _) = WalletFile::create(&wb).unwrap();
    let (a_addr, b_addr) = (a_wallet.address().unwrap(), b_wallet.address().unwrap());
    let a = App::start(cfg(Network::Fast, &d, "a", Some(wa), true, vec![], true)).unwrap();
    let a_listen = a.handle.local_addr.unwrap();
    let b = App::start(cfg(Network::Fast, &d, "b", Some(wb), false, vec![a_listen], false)).unwrap();

    wait_until("saldo gastable en A", 120, || a.balance().map_or(false, |s| !s.contains("gastable ahora: 0.00000000")));
    // antes de pagar: solo hay minado, y B no tiene nada
    let h0 = a.history(100).unwrap();
    assert!(!h0.is_empty() && h0.iter().all(|e| e.kind == Kind::Mined && e.txid.is_none()), "{h0:?}");
    assert!(b.history(100).unwrap().is_empty());

    a.send(&encode(&b_addr), 7 * COIN + 5, None).unwrap();

    // B: el pago aparece (pendiente o confirmado) y acaba confirmado, con A como origen
    wait_until("pago recibido confirmado en B", 120, || {
        b.history(100).unwrap().iter().any(|e| e.kind == Kind::Received && e.height.is_some() && e.confirmations >= 1)
    });
    let hb = b.history(100).unwrap();
    assert_eq!(hb.len(), 1, "{hb:?}");
    assert_eq!((hb[0].kind, hb[0].amount, hb[0].counterparty), (Kind::Received, 7 * COIN + 5, Some(a_addr)));
    assert!(hb[0].timestamp.is_some() && hb[0].txid.is_some());

    // A: el envío aparece una vez, a B, por la cantidad pagada (sin el cambio) y más nuevo que lo minado
    wait_until("envío confirmado en A", 120, || {
        a.history(500).unwrap().iter().any(|e| e.kind == Kind::Sent && e.height.is_some())
    });
    let ha = a.history(500).unwrap();
    let sent: Vec<_> = ha.iter().filter(|e| e.kind == Kind::Sent).collect();
    assert_eq!(sent.len(), 1, "{ha:?}");
    assert_eq!((sent[0].amount, sent[0].counterparty), (7 * COIN + 5, Some(b_addr)));
    // orden: de más nuevo a más viejo
    let heights: Vec<u64> = ha.iter().filter_map(|e| e.height).collect();
    assert!(heights.windows(2).all(|w| w[0] >= w[1]), "{heights:?}");
    // lo minado reciente aún no madura; lo antiguo sí
    let mined: Vec<_> = ha.iter().filter(|e| e.kind == Kind::Mined).collect();
    assert!(mined.iter().any(|e| e.matures_in == 0));
    // el límite se respeta
    assert_eq!(a.history(2).unwrap().len(), 2);
    let _ = a_addr;
    b.shutdown();
    a.shutdown();
}
