use armax_chain::block::genesis_block;
use armax_chain::block::{Coinbase, Output};
use armax_chain::{Address, DamperParams};
use armax_share::{make_extra, Share};
use armax_keys::ed25519::Keypair;
use armax_keys::tx::{OutPoint, Transaction, TxOut};
use armax_ledger::Ledger;
use armax_net::codec::*;
use armax_pow::U256;

fn samples() -> Vec<Message> {
    let mut l = Ledger::new(DamperParams::MAINNET, genesis_block(1_800_000_000, b"codec"), 1).unwrap();
    let fb = l.build_template(&[(Address([3; 32]), 1_000_000)], 1_800_000_300, vec![1, 2, 3], &[]).unwrap();
    let kp = Keypair::from_seed([5; 32]);
    let tx = Transaction::build_signed(
        &[(OutPoint { txid: [8; 32], index: 1 }, &kp)],
        vec![TxOut { address: Address([4; 32]), amount: 1234 }],
        &[0; 32],
    )
    .unwrap();
    let ids = vec![[1u8; 32], [2; 32], [3; 32]];
    vec![
        Message::Version(Version {
            protocol: PROTOCOL_VERSION,
            services: SERVICE_SERVE,
            genesis: [1; 32],
            tip: [2; 32],
            tip_height: 777,
            tip_work: U256::from_u64(123_456_789),
            nonce: 99,
            listen_port: 8333,
        }),
        Message::Verack,
        Message::Ping(5),
        Message::Pong(6),
        Message::GetAddr,
        Message::Addr(vec![NetAddr { last_seen: 42, ..NetAddr::v4(1, 2, 3, 4, 8000) }, NetAddr::v4(5, 6, 7, 8, 9)]),
        Message::GetHeaders { locator: ids.clone() },
        Message::Headers(headers(3)),
        Message::GetBlocks(ids.clone()),
        Message::Block(Box::new(fb)),
        Message::NotFound(ids.clone()),
        Message::InvBlocks(ids.clone()),
        Message::InvTxs(ids.clone()),
        Message::GetTxs(ids),
        Message::Tx(Box::new(tx)),
        Message::Headers(vec![]),
        Message::InvShares(vec![[7; 32], [8; 32]]),
        Message::GetShareChain { from: [9; 32], max: 64 },
        Message::Shares(vec![sample_share(1), sample_share(2)]),
        Message::Shares(vec![]),
    ]
}

fn sample_share(i: u8) -> Share {
    let mut header = headers(1).remove(0);
    header.nonce = i as u64;
    let coinbase = Coinbase {
        height: 1,
        fees: 0,
        outputs: vec![
            Output { address: Address([1; 32]), share_ppm: 600_000, amount: 15 },
            Output { address: Address([2; 32]), share_ppm: 400_000, amount: 10 },
        ],
        extra: make_extra(&[i; 32], &Address([3; 32])),
    };
    Share { header, coinbase, txs: vec![] }
}

fn headers(n: usize) -> Vec<armax_pow::BlockHeader> {
    (0..n)
        .map(|i| armax_pow::BlockHeader {
            version: 1,
            height: i as u64,
            prev_hash: [i as u8; 32],
            merkle_root: [7; 32],
            timestamp: 1_000 + i as u64,
            target: armax_pow::U256::from_u64(1 << 40),
            nonce: i as u64 * 3,
        })
        .collect()
}

#[test]
fn every_message_roundtrips() {
    for m in samples() {
        assert_eq!(decode_one(&m.encode()), Ok(m.clone()), "{m:?}");
    }
}

#[test]
fn a_stream_split_at_any_point_decodes_the_same() {
    let msgs = samples();
    let wire: Vec<u8> = msgs.iter().flat_map(|m| m.encode()).collect();
    for chunk in [1usize, 2, 7, 13, 64, 1000, wire.len()] {
        let mut d = Decoder::new();
        let mut got = vec![];
        for part in wire.chunks(chunk) {
            d.push(part);
            while let Some(m) = d.next().unwrap() {
                got.push(m);
            }
        }
        assert_eq!(got, msgs, "chunk={chunk}");
        assert_eq!(d.buffered(), 0);
    }
}

#[test]
fn truncated_frames_never_decode() {
    for m in samples() {
        let f = m.encode();
        for cut in (0..f.len()).step_by(3) {
            assert!(decode_one(&f[..cut]).is_err(), "{m:?} cut={cut}");
        }
    }
}

#[test]
fn corruption_is_detected() {
    let f = Message::Ping(1).encode();
    let mut bad = f.clone();
    bad[0] ^= 1;
    assert_eq!(decode_one(&bad), Err(CodecError::BadMagic));
    let mut bad = f.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert_eq!(decode_one(&bad), Err(CodecError::BadChecksum));
    // longitud absurda: se rechaza sin esperar a recibir 4 GiB
    let mut huge = f.clone();
    huge[5..9].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(decode_one(&huge), Err(CodecError::TooLarge(_))));
    // comando desconocido con checksum válido
    let mut unk = f.clone();
    unk[4] = 200;
    assert_eq!(decode_one(&unk), Err(CodecError::UnknownCommand(200)));
    // bytes basura al principio
    let mut d = Decoder::new();
    d.push(b"GET / HTTP/1.1\r\n\r\n");
    assert_eq!(d.next(), Err(CodecError::BadMagic));
}

#[test]
fn lists_are_bounded() {
    // más ids de los permitidos, con trama y checksum válidos
    let ids: Vec<[u8; 32]> = vec![[1; 32]; MAX_GETBLOCKS + 1];
    let f = Message::GetBlocks(ids).encode();
    assert!(matches!(decode_one(&f), Err(CodecError::Malformed(_))));
    let loc: Vec<[u8; 32]> = vec![[1; 32]; MAX_LOCATOR + 1];
    assert!(decode_one(&Message::GetHeaders { locator: loc }.encode()).is_err());
    let hs = headers(MAX_HEADERS + 1);
    assert!(matches!(decode_one(&Message::Headers(hs).encode()), Err(CodecError::Malformed(_))));
    // una cabecera truncada dentro de un lote
    let mut f = Message::Headers(headers(2)).encode();
    let n = f.len();
    f.truncate(n - 5);
    assert!(decode_one(&f).is_err());
    let addrs = vec![NetAddr::v4(1, 1, 1, 1, 1); MAX_ADDRS + 1];
    assert!(decode_one(&Message::Addr(addrs).encode()).is_err());
}

#[test]
fn trailing_bytes_in_a_payload_are_rejected() {
    // Verack con 1 byte de carga
    let payload = [0u8];
    let mut f = Vec::new();
    f.extend_from_slice(&MAGIC);
    f.push(2);
    f.extend_from_slice(&1u32.to_le_bytes());
    f.extend_from_slice(&armax_vm::sha256::sha256(&payload)[..4]);
    f.extend_from_slice(&payload);
    assert!(matches!(decode_one(&f), Err(CodecError::Malformed(_))));
}

#[test]
fn share_lists_are_bounded() {
    // una cuenta de 65 se rechaza por la cuenta, antes de mirar el contenido
    let mut payload = vec![];
    payload.extend_from_slice(&65u16.to_le_bytes());
    payload.extend_from_slice(&[0u8; 8]);
    let mut f = vec![];
    f.extend_from_slice(b"ARMX");
    f.push(18);
    f.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    f.extend_from_slice(&armax_vm::sha256::sha256(&payload)[..4]);
    f.extend_from_slice(&payload);
    assert!(matches!(decode_one(&f), Err(CodecError::Malformed(_))));
}
