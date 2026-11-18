//! Imprime los digests de referencia (para fijarlos en tests/kat.rs).
use armax_vm::{pow_hash, Native, OpTable, Params};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let p = Params::TEST;
    let mut scratch = vec![0u8; p.scratch_bytes];
    let t0 = OpTable::identity();
    let t1 = OpTable::for_epoch(&[0xAB; 32]);
    for (label, table, input) in [
        ("identity/empty", &t0, &b""[..]),
        ("identity/abc", &t0, &b"abc"[..]),
        ("identity/hdr0", &t0, &[0u8; 80][..]),
        ("epoch-ab/abc", &t1, &b"abc"[..]),
    ] {
        let h = pow_hash::<Native>(&p, table, input, &mut scratch);
        println!("{label}: {}", hex(&h));
    }
}
