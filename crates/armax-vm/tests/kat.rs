//! Vectores de regresión de la VM (parámetros `Params::TEST`).
//!
//! OJO: estos valores los produjo esta misma implementación (no hay una
//! referencia independiente). Sirven para detectar cambios accidentales y,
//! sobre todo, para comprobar que **ARM64 con intrínsecos AES produce los mismos
//! bytes que el backend portable**: correr `cargo test` en un dispositivo ARM64.

use armax_vm::{pow_hash, Native, OpTable, Params, Portable};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn run<B: armax_vm::Aes>(table: &OpTable, input: &[u8]) -> String {
    let p = Params::TEST;
    let mut scratch = vec![0u8; p.scratch_bytes];
    hex(&pow_hash::<B>(&p, table, input, &mut scratch))
}

#[test]
fn known_answers() {
    let t0 = OpTable::identity();
    let t1 = OpTable::for_epoch(&[0xAB; 32]);
    assert_eq!(run::<Native>(&t0, b""), "a74953cc9189045bb608a680bf1aac1839be2ec45467f557855c3fc5a23e8d02");
    assert_eq!(run::<Native>(&t0, b"abc"), "0615879a71bd51f72b62411d5ab6939d0310ce72749bb8faf645b212e92f7f3f");
    assert_eq!(run::<Native>(&t0, &[0u8; 80]), "12a10d0fbd268b3405ad7f61183be523bc499bded4b7e02bbd17a49f83e1468f");
    assert_eq!(run::<Native>(&t1, b"abc"), "a074a7b1d8a9b0e0f6f0c28bfbcbb8eb52fba98d191eef82f062e8eebab0db3f");
}

#[test]
fn native_equals_portable() {
    let t = OpTable::for_epoch(&[9u8; 32]);
    for n in 0u32..6 {
        let input = n.to_le_bytes();
        assert_eq!(run::<Native>(&t, &input), run::<Portable>(&t, &input));
    }
}

#[test]
fn nonce_and_epoch_change_the_digest() {
    let t0 = OpTable::identity();
    let t1 = OpTable::for_epoch(&[0xAB; 32]);
    let mut seen = std::collections::HashSet::new();
    for n in 0u32..16 {
        assert!(seen.insert(run::<Portable>(&t0, &n.to_le_bytes())));
    }
    assert_ne!(run::<Portable>(&t0, b"abc"), run::<Portable>(&t1, b"abc"));
}

#[test]
fn scratchpad_buffer_is_reusable_across_attempts() {
    // El minero reutiliza el mismo buffer para todos los nonces: el resultado
    // no puede depender de lo que quedó escrito por el intento anterior.
    let p = Params::TEST;
    let t = OpTable::identity();
    let mut dirty = vec![0xA5u8; p.scratch_bytes];
    let mut clean = vec![0u8; p.scratch_bytes];
    let _ = pow_hash::<Portable>(&p, &t, b"previous", &mut dirty);
    let a = pow_hash::<Portable>(&p, &t, b"abc", &mut dirty);
    let b = pow_hash::<Portable>(&p, &t, b"abc", &mut clean);
    assert_eq!(a, b);
}

#[test]
fn program_executes_every_opcode_family_without_panicking() {
    // Muchas semillas distintas => programas distintos: ejercita todas las ramas del intérprete.
    let p = Params { scratch_bytes: 1 << 16, prog_len: 256, iterations: 8 };
    let t = OpTable::identity();
    let mut scratch = vec![0u8; p.scratch_bytes];
    for n in 0u32..200 {
        let _ = pow_hash::<Portable>(&p, &t, &n.to_le_bytes(), &mut scratch);
    }
}
