//! ChaCha20-Poly1305 (RFC 8439): cifrado autenticado con datos asociados.

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

fn quarter(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

fn chacha_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut init = [0u32; 16];
    init[..4].copy_from_slice(&[0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
    for i in 0..8 {
        init[4 + i] = u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
    }
    init[12] = counter;
    for i in 0..3 {
        init[13 + i] = u32::from_le_bytes(nonce[4 * i..4 * i + 4].try_into().unwrap());
    }
    let mut s = init;
    for _ in 0..10 {
        quarter(&mut s, 0, 4, 8, 12);
        quarter(&mut s, 1, 5, 9, 13);
        quarter(&mut s, 2, 6, 10, 14);
        quarter(&mut s, 3, 7, 11, 15);
        quarter(&mut s, 0, 5, 10, 15);
        quarter(&mut s, 1, 6, 11, 12);
        quarter(&mut s, 2, 7, 8, 13);
        quarter(&mut s, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&s[i].wrapping_add(init[i]).to_le_bytes());
    }
    out
}

fn chacha_xor(key: &[u8; 32], nonce: &[u8; 12], first_counter: u32, data: &mut [u8]) {
    for (n, chunk) in data.chunks_mut(64).enumerate() {
        let ks = chacha_block(key, first_counter.wrapping_add(n as u32), nonce);
        for (b, k) in chunk.iter_mut().zip(ks.iter()) {
            *b ^= k;
        }
    }
}

/// Poly1305 de un solo uso (RFC 8439 §2.5), aritmética en 5 miembros de 26 bits.
fn poly1305(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    let le = |b: &[u8]| u32::from_le_bytes(b[..4].try_into().unwrap()) as u64;
    const M: u64 = 0x3ff_ffff;
    let r0 = le(&key[0..]) & 0x3ff_ffff;
    let r1 = (le(&key[3..]) >> 2) & 0x3ff_ff03;
    let r2 = (le(&key[6..]) >> 4) & 0x3ff_c0ff;
    let r3 = (le(&key[9..]) >> 6) & 0x3f0_3fff;
    let r4 = (le(&key[12..]) >> 8) & 0x00f_ffff;
    let (s1, s2, s3, s4) = (r1 * 5, r2 * 5, r3 * 5, r4 * 5);
    let (mut h0, mut h1, mut h2, mut h3, mut h4) = (0u64, 0u64, 0u64, 0u64, 0u64);

    for chunk in msg.chunks(16) {
        let mut b = [0u8; 20];
        b[..chunk.len()].copy_from_slice(chunk);
        let hibit = if chunk.len() == 16 {
            1u64 << 24
        } else {
            b[chunk.len()] = 1;
            0
        };
        h0 += le(&b[0..]) & M;
        h1 += (le(&b[3..]) >> 2) & M;
        h2 += (le(&b[6..]) >> 4) & M;
        h3 += (le(&b[9..]) >> 6) & M;
        h4 += (le(&b[12..]) >> 8) | hibit;

        let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let mut d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let mut d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let mut d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let mut d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
        let mut c = d0 >> 26;
        h0 = d0 & M;
        d1 += c;
        c = d1 >> 26;
        h1 = d1 & M;
        d2 += c;
        c = d2 >> 26;
        h2 = d2 & M;
        d3 += c;
        c = d3 >> 26;
        h3 = d3 & M;
        d4 += c;
        c = d4 >> 26;
        h4 = d4 & M;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= M;
        h1 += c;
    }

    // reducción final completa
    let mut c = h1 >> 26;
    h1 &= M;
    h2 += c;
    c = h2 >> 26;
    h2 &= M;
    h3 += c;
    c = h3 >> 26;
    h3 &= M;
    h4 += c;
    c = h4 >> 26;
    h4 &= M;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= M;
    h1 += c;

    // g = h + 5 - 2^130; se elige h o g sin ramas
    let mut g0 = h0 + 5;
    c = g0 >> 26;
    g0 &= M;
    let mut g1 = h1 + c;
    c = g1 >> 26;
    g1 &= M;
    let mut g2 = h2 + c;
    c = g2 >> 26;
    g2 &= M;
    let mut g3 = h3 + c;
    c = g3 >> 26;
    g3 &= M;
    let g4 = (h4 + c).wrapping_sub(1 << 26);
    let mask = (g4 >> 63).wrapping_sub(1); // g4 "negativo" (bit alto) → 0: se queda h
    let nmask = !mask;
    h0 = (h0 & nmask) | (g0 & mask);
    h1 = (h1 & nmask) | (g1 & mask);
    h2 = (h2 & nmask) | (g2 & mask);
    h3 = (h3 & nmask) | (g3 & mask);
    h4 = (h4 & nmask) | (g4 & M & mask);

    let w0 = (h0 | (h1 << 26)) as u32;
    let w1 = ((h1 >> 6) | (h2 << 20)) as u32;
    let w2 = ((h2 >> 12) | (h3 << 14)) as u32;
    let w3 = ((h3 >> 18) | (h4 << 8)) as u32;
    let mut f = w0 as u64 + le(&key[16..]);
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&(f as u32).to_le_bytes());
    f = w1 as u64 + le(&key[20..]) + (f >> 32);
    out[4..8].copy_from_slice(&(f as u32).to_le_bytes());
    f = w2 as u64 + le(&key[24..]) + (f >> 32);
    out[8..12].copy_from_slice(&(f as u32).to_le_bytes());
    f = w3 as u64 + le(&key[28..]) + (f >> 32);
    out[12..16].copy_from_slice(&(f as u32).to_le_bytes());
    out
}

fn tag_of(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let otk: [u8; 32] = chacha_block(key, 0, nonce)[..32].try_into().unwrap();
    let pad = |n: usize| (16 - n % 16) % 16;
    let mut m = Vec::with_capacity(aad.len() + ct.len() + 48);
    m.extend_from_slice(aad);
    m.extend(std::iter::repeat(0u8).take(pad(aad.len())));
    m.extend_from_slice(ct);
    m.extend(std::iter::repeat(0u8).take(pad(ct.len())));
    m.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    m.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    poly1305(&otk, &m)
}

/// Cifra `plaintext`; devuelve `ciphertext || etiqueta(16)`.
pub fn seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut out = plaintext.to_vec();
    chacha_xor(key, nonce, 1, &mut out);
    let tag = tag_of(key, nonce, aad, &out);
    out.extend_from_slice(&tag);
    out
}

/// Descifra `ciphertext || etiqueta`; `None` si la etiqueta no coincide (comparación en tiempo
/// constante).
pub fn open(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < TAG_LEN {
        return None;
    }
    let (ct, tag) = sealed.split_at(sealed.len() - TAG_LEN);
    let expect = tag_of(key, nonce, aad, ct);
    let diff = expect.iter().zip(tag).fold(0u8, |a, (x, y)| a | (x ^ y));
    if diff != 0 {
        return None;
    }
    let mut out = ct.to_vec();
    chacha_xor(key, nonce, 1, &mut out);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn chacha20_block_rfc8439() {
        let key: [u8; 32] = (0u8..32).collect::<Vec<_>>().try_into().unwrap();
        let nonce: [u8; 12] = unhex("000000090000004a00000000").try_into().unwrap();
        let b = chacha_block(&key, 1, &nonce);
        assert_eq!(hex(&b[..16]), "10f1e7e4d13b5915500fdd1fa32071c4");
        assert_eq!(hex(&b[48..]), "b5129cd1de164eb9cbd083e8a2503c4e");
    }

    #[test]
    fn poly1305_rfc8439() {
        let key: [u8; 32] = unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b").try_into().unwrap();
        assert_eq!(hex(&poly1305(&key, b"Cryptographic Forum Research Group")), "a8061dc1305136c6c22b8baf0c0127a9");
    }

    #[test]
    fn aead_rfc8439() {
        let key: [u8; 32] = (0x80u8..0xa0).collect::<Vec<_>>().try_into().unwrap();
        let nonce: [u8; 12] = unhex("070000004041424344454647").try_into().unwrap();
        let aad = unhex("50515253c0c1c2c3c4c5c6c7");
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let sealed = seal(&key, &nonce, &aad, pt);
        assert_eq!(hex(&sealed[..16]), "d31a8d34648e60db7b86afbc53ef7ec2");
        assert_eq!(hex(&sealed[sealed.len() - 16..]), "1ae10b594f09e26a7e902ecbd0600691");
        assert_eq!(open(&key, &nonce, &aad, &sealed).unwrap(), pt);
    }

    #[test]
    fn tampering_is_rejected() {
        let key = [7u8; 32];
        let nonce = [1u8; 12];
        let sealed = seal(&key, &nonce, b"aad", b"hola mundo");
        assert!(open(&key, &nonce, b"aad", &sealed).is_some());
        assert!(open(&key, &nonce, b"aae", &sealed).is_none());
        assert!(open(&key, &[2u8; 12], b"aad", &sealed).is_none());
        assert!(open(&[8u8; 32], &nonce, b"aad", &sealed).is_none());
        for i in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[i] ^= 1;
            assert!(open(&key, &nonce, b"aad", &bad).is_none(), "byte {i}");
        }
        assert!(open(&key, &nonce, b"aad", &sealed[..5]).is_none());
        // vacío y de varios tamaños alrededor de los bloques
        for n in [0usize, 1, 15, 16, 17, 63, 64, 65, 200] {
            let pt = vec![0xa5u8; n];
            assert_eq!(open(&key, &nonce, b"", &seal(&key, &nonce, b"", &pt)).unwrap(), pt);
        }
    }
}
