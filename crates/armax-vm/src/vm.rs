//! Intérprete de la VM de ARMax y pipeline completo de PoW.
//!
//! Pipeline por intento (`pow_hash`):
//!   1. `seed = SHA256(input)` (input = cabecera con nonce).
//!   2. Se genera el programa (`prog_len` instrucciones) y se **rellena todo el
//!      scratchpad** con la cadena AES secuencial. La última línea de la cadena
//!      se guarda y entra en el digest final: obliga a calcular la cadena entera.
//!   3. `iterations` pasadas del programa; cada pasada termina con un
//!      read-modify-write de una línea de 64 B elegida por los registros.
//!   4. Digest final = SHA256(registros || vectores || cola de la cadena || semilla).
//!
//! Terminación garantizada: las ramas solo saltan hacia delante.
//! Determinismo: solo aritmética entera; todo en little-endian explícito.

use core::marker::PhantomData;

use crate::aes::Aes;
use crate::gen::{gen_program, AesGen, DOM_REGS, DOM_SCRATCH};
use crate::isa::{AluOp, Cond, Instr, OpTable, Sem, UnOp, VOp};
use crate::sha256::{sha256, sha256_cat};

/// Parámetros de la VM. `CONSENSUS` son valores **provisionales** hasta medir en dispositivos reales.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    pub scratch_bytes: usize,
    pub prog_len: usize,
    pub iterations: u32,
}

impl Params {
    pub const CONSENSUS: Params = Params {
        scratch_bytes: 384 * 1024 * 1024,
        prog_len: 256,
        // Medido en ARM64 real: con 2048 el relleno era el 79 % del intento (PoW limitado por
        // ancho de banda); con 16384 baja al 35 % y domina el acceso aleatorio.
        iterations: 16384,
    };

    /// Tamaños reducidos para tests rápidos (NO válidos en consenso).
    pub const TEST: Params = Params {
        scratch_bytes: 1 << 20,
        prog_len: 64,
        iterations: 64,
    };

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.scratch_bytes < 4096 || self.scratch_bytes % 64 != 0 {
            return Err("scratch_bytes debe ser >= 4096 y múltiplo de 64");
        }
        if self.prog_len == 0 || self.prog_len % 8 != 0 {
            return Err("prog_len debe ser > 0 y múltiplo de 8");
        }
        if self.iterations == 0 {
            return Err("iterations debe ser > 0");
        }
        Ok(())
    }
}

/// Reducción de rango sin sesgo de módulo: `floor(x * n / 2^64)`.
#[inline(always)]
fn reduce(x: u64, n: u64) -> u64 {
    ((x as u128 * n as u128) >> 64) as u64
}

#[inline(always)]
fn alu(op: AluOp, d: u64, s: u64) -> u64 {
    match op {
        AluOp::Add => d.wrapping_add(s),
        AluOp::Sub => d.wrapping_sub(s),
        AluOp::RSub => s.wrapping_sub(d),
        AluOp::Xor => d ^ s,
        AluOp::And => d & s,
        AluOp::Or => d | s,
        AluOp::AndN => d & !s,
        AluOp::Xnor => !(d ^ s),
        AluOp::Mul => d.wrapping_mul(s),
        AluOp::UMulH => ((d as u128 * s as u128) >> 64) as u64,
        AluOp::SMulH => (((d as i64 as i128) * (s as i64 as i128)) >> 64) as u64,
        AluOp::Rol => d.rotate_left((s & 63) as u32),
        AluOp::Ror => d.rotate_right((s & 63) as u32),
        AluOp::Shl => d << (s & 63),
        AluOp::Shr => d >> (s & 63),
        AluOp::Sar => ((d as i64) >> (s & 63)) as u64,
    }
}

#[inline(always)]
fn unary(op: UnOp, x: u64) -> u64 {
    match op {
        UnOp::Neg => x.wrapping_neg(),
        UnOp::Not => !x,
        UnOp::Bswap => x.swap_bytes(),
        UnOp::Clz => x.leading_zeros() as u64,
        UnOp::Ctz => x.trailing_zeros() as u64,
        UnOp::Popcnt => x.count_ones() as u64,
        UnOp::Rbit => x.reverse_bits(),
        UnOp::Swap32 => x.rotate_left(32),
    }
}

#[inline(always)]
fn fused(v: u8, d: u64, s: u64, imm: u32) -> u64 {
    let isx = imm as i32 as i64 as u64;
    match v & 7 {
        0 => d.wrapping_mul(s).wrapping_add(isx),
        1 => d.wrapping_mul((imm as u64) | 1).wrapping_add(s),
        2 => d ^ s.rotate_left(imm & 63),
        3 => (d ^ s).wrapping_mul((imm as u64) | 1),
        4 => d.wrapping_add(s.wrapping_mul(s)),
        5 => (((d as u128 * s as u128) >> 64) as u64) ^ d.rotate_left(imm & 63),
        6 => d.wrapping_sub(s & isx),
        _ => d.rotate_left(imm & 63).wrapping_add(s ^ isx),
    }
}

#[inline(always)]
fn cond(c: Cond, a: u64, b: u64) -> bool {
    match c {
        Cond::Eq => a == b,
        Cond::Ne => a != b,
        Cond::Lt => (a as i64) < (b as i64),
        Cond::Ge => (a as i64) >= (b as i64),
        Cond::Ltu => a < b,
        Cond::Geu => a >= b,
    }
}

#[inline(always)]
fn mix_addr(v: u8, a: u64, d: u64, imm: u32) -> u64 {
    let isx = imm as i32 as i64 as u64;
    match v & 7 {
        0 => a,
        1 => a.wrapping_add(isx),
        2 => a ^ (imm as u64),
        3 => a.wrapping_mul((imm as u64) | 1),
        4 => a.rotate_left(13) ^ d,
        5 => a.wrapping_add(d),
        6 => (a ^ d).rotate_right(7),
        _ => a.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (imm as u64),
    }
}

#[inline(always)]
fn v2b(x: [u64; 2]) -> [u8; 16] {
    let mut o = [0u8; 16];
    o[..8].copy_from_slice(&x[0].to_le_bytes());
    o[8..].copy_from_slice(&x[1].to_le_bytes());
    o
}

#[inline(always)]
fn b2v(b: [u8; 16]) -> [u64; 2] {
    [
        u64::from_le_bytes(b[..8].try_into().unwrap()),
        u64::from_le_bytes(b[8..].try_into().unwrap()),
    ]
}

#[inline(always)]
fn valu(op: VOp, a: [u64; 2], b: [u64; 2], imm: u32) -> [u64; 2] {
    let sh = imm & 63;
    match op {
        VOp::Add64 => [a[0].wrapping_add(b[0]), a[1].wrapping_add(b[1])],
        VOp::Sub64 => [a[0].wrapping_sub(b[0]), a[1].wrapping_sub(b[1])],
        VOp::Add32 => {
            let f = |x: u64, y: u64| {
                let lo = (x as u32).wrapping_add(y as u32) as u64;
                let hi = ((x >> 32) as u32).wrapping_add((y >> 32) as u32) as u64;
                lo | (hi << 32)
            };
            [f(a[0], b[0]), f(a[1], b[1])]
        }
        VOp::Xor => [a[0] ^ b[0], a[1] ^ b[1]],
        VOp::And => [a[0] & b[0], a[1] & b[1]],
        VOp::Or => [a[0] | b[0], a[1] | b[1]],
        VOp::AndN => [a[0] & !b[0], a[1] & !b[1]],
        VOp::Mul32 => [
            (a[0] & 0xFFFF_FFFF) * (b[0] & 0xFFFF_FFFF),
            (a[1] & 0xFFFF_FFFF) * (b[1] & 0xFFFF_FFFF),
        ],
        VOp::Rol64 => [a[0].rotate_left(sh), a[1].rotate_left(sh)],
        VOp::Ror64 => [a[0].rotate_right(sh), a[1].rotate_right(sh)],
        VOp::Shl64 => [a[0] << sh, a[1] << sh],
        VOp::Shr64 => [a[0] >> sh, a[1] >> sh],
        VOp::Swap => [a[1], a[0]],
        VOp::Rev8 => [a[0].swap_bytes(), a[1].swap_bytes()],
        VOp::Cnt8 => {
            let mut bytes = v2b(a);
            for x in bytes.iter_mut() {
                *x = x.count_ones() as u8;
            }
            b2v(bytes)
        }
        VOp::Ext => {
            let x = ((a[1] as u128) << 64) | a[0] as u128;
            let y = x.rotate_left(8 * (imm & 15));
            [(y as u64) ^ b[0], ((y >> 64) as u64) ^ b[1]]
        }
    }
}

pub struct Vm<'a, B: Aes> {
    r: [u64; 8],
    v: [[u64; 2]; 8],
    mem: &'a mut [u8],
    n8: u64,
    n4: u64,
    n16: u64,
    n64: u64,
    _b: PhantomData<B>,
}

impl<'a, B: Aes> Vm<'a, B> {
    /// Registros iniciales derivados de la semilla (192 bytes del generador AES).
    pub fn new(seed: &[u8; 32], mem: &'a mut [u8]) -> Self {
        let mut init = [0u8; 192];
        AesGen::<B>::new(seed, DOM_REGS).fill(&mut init);
        let mut r = [0u64; 8];
        for (i, x) in r.iter_mut().enumerate() {
            *x = u64::from_le_bytes(init[8 * i..8 * i + 8].try_into().unwrap());
        }
        let mut v = [[0u64; 2]; 8];
        for (i, x) in v.iter_mut().enumerate() {
            let o = 64 + 16 * i;
            *x = b2v(init[o..o + 16].try_into().unwrap());
        }
        let len = mem.len() as u64;
        Self { r, v, n8: len / 8, n4: len / 4, n16: len / 16, n64: len / 64, mem, _b: PhantomData }
    }

    #[inline(always)]
    fn ld64(&self, at: usize) -> u64 {
        u64::from_le_bytes(self.mem[at..at + 8].try_into().unwrap())
    }
    #[inline(always)]
    fn st64(&mut self, at: usize, x: u64) {
        self.mem[at..at + 8].copy_from_slice(&x.to_le_bytes());
    }
    #[inline(always)]
    fn ld32(&self, at: usize) -> u64 {
        u32::from_le_bytes(self.mem[at..at + 4].try_into().unwrap()) as u64
    }
    #[inline(always)]
    fn ld128(&self, at: usize) -> [u64; 2] {
        [self.ld64(at), self.ld64(at + 8)]
    }
    #[inline(always)]
    fn st128(&mut self, at: usize, x: [u64; 2]) {
        self.st64(at, x[0]);
        self.st64(at + 8, x[1]);
    }
    #[inline(always)]
    fn a8(&self, x: u64) -> usize {
        reduce(x, self.n8) as usize * 8
    }
    #[inline(always)]
    fn a4(&self, x: u64) -> usize {
        reduce(x, self.n4) as usize * 4
    }
    #[inline(always)]
    fn a16(&self, x: u64) -> usize {
        reduce(x, self.n16) as usize * 16
    }

    #[inline(always)]
    fn aes_key(&self, var: u8, d: usize, s: usize, imm: u32) -> [u64; 2] {
        let k = (imm as u64) | ((imm as u64) << 32);
        match var & 7 {
            0 => self.v[s],
            1 => [self.v[s][0] ^ k, self.v[s][1] ^ k],
            2 => [self.r[s], self.r[d]],
            3 => [self.r[s] ^ k, self.r[s].rotate_left(32)],
            4 => [self.v[s][1], self.v[s][0]],
            5 => self.v[(s + 1) & 7],
            6 => [self.r[s], self.r[s]],
            _ => [k.wrapping_mul(0x9E37_79B9_7F4A_7C15), k.wrapping_mul(0xC2B2_AE3D_27D4_EB4F)],
        }
    }

    /// Ejecuta el programa una vez (una "iteración" sin el commit final).
    pub fn exec(&mut self, prog: &[Instr], table: &OpTable) {
        let mut pc = 0usize;
        while pc < prog.len() {
            let ins = prog[pc];
            pc += 1;
            let d = ins.dst as usize;
            let s = ins.src as usize;
            let imm = ins.imm;
            let isx = imm as i32 as i64 as u64;
            match table.sem[ins.op as usize] {
                Sem::AluRR(op) => self.r[d] = alu(op, self.r[d], self.r[s]),
                Sem::AluRI(op) => self.r[d] = alu(op, self.r[d], isx),
                Sem::Unary(op) => self.r[d] = self.r[d].wrapping_add(unary(op, self.r[s])),
                Sem::Fused(var) => self.r[d] = fused(var, self.r[d], self.r[s], imm),
                Sem::Load64(var) => {
                    let at = self.a8(mix_addr(var, self.r[s], self.r[d], imm));
                    self.r[d] = self.ld64(at);
                }
                Sem::Load32(var) => {
                    let at = self.a4(mix_addr(var, self.r[s], self.r[d], imm));
                    self.r[d] = self.ld32(at);
                }
                Sem::Store64(var) => {
                    let at = self.a8(mix_addr(var, self.r[s], self.r[d], imm));
                    self.st64(at, self.r[d]);
                }
                Sem::Rmw(var) => {
                    let at = self.a8(mix_addr(var & 3, self.r[s], self.r[d], imm));
                    let old = self.ld64(at);
                    let new = if var < 4 { old ^ self.r[d] } else { old.wrapping_add(self.r[d]) };
                    self.st64(at, new);
                    self.r[d] = old;
                }
                Sem::VLoad(var) => {
                    let at = self.a16(mix_addr(var, self.r[s], self.r[d], imm));
                    self.v[d] = self.ld128(at);
                }
                Sem::VStore(var) => {
                    let at = self.a16(mix_addr(var, self.r[s], self.r[d], imm));
                    self.st128(at, self.v[d]);
                }
                Sem::AesEnc(var) => {
                    let key = self.aes_key(var, d, s, imm);
                    self.v[d] = b2v(B::enc_round(v2b(self.v[d]), v2b(key)));
                }
                Sem::AesDec(var) => {
                    let key = self.aes_key(var, d, s, imm);
                    self.v[d] = b2v(B::dec_round(v2b(self.v[d]), v2b(key)));
                }
                Sem::VAlu(op) => self.v[d] = valu(op, self.v[d], self.v[s], imm),
                Sem::Xfer(var) => match var & 7 {
                    0 => self.r[d] = self.v[s][0],
                    1 => self.r[d] = self.v[s][1],
                    2 => self.v[d][0] = self.r[s],
                    3 => self.v[d][1] = self.r[s],
                    4 => self.r[d] = self.v[s][0] ^ self.v[s][1],
                    5 => self.v[d] = [self.r[s], self.r[s]],
                    6 => {
                        self.v[d][0] ^= self.r[s];
                        self.v[d][1] ^= self.r[s].rotate_left(32);
                    }
                    _ => self.v[d] = [isx, !isx.wrapping_mul(0x9E37_79B9_7F4A_7C15)],
                },
                Sem::BranchRR(c) => {
                    if cond(c, self.r[d], self.r[s]) {
                        pc += 1 + (ins.aux & 3) as usize;
                    }
                }
                Sem::BranchRI(c) => {
                    if cond(c, self.r[d], isx) {
                        pc += 1 + (ins.aux & 3) as usize;
                    }
                }
                Sem::BitBranch(var) => {
                    let x = if var >= 2 { self.r[d] ^ self.r[s] } else { self.r[d] };
                    let bit = (x >> (ins.aux & 63)) & 1;
                    let taken = if var & 1 == 0 { bit == 1 } else { bit == 0 };
                    if taken {
                        pc += 1 + (ins.aux >> 6) as usize;
                    }
                }
                Sem::Cmov(var) => {
                    let (a, b) = (self.r[d], self.r[s]);
                    let c = match var & 7 {
                        0 => a == b,
                        1 => a != b,
                        2 => (a as i64) < (b as i64),
                        3 => (a as i64) >= (b as i64),
                        4 => a < b,
                        5 => a >= b,
                        6 => ((a ^ b) & 1) == 1,
                        _ => ((a ^ b) & 1) == 0,
                    };
                    self.r[d] = if c { self.r[(ins.aux & 7) as usize] } else { a.wrapping_add(isx) };
                }
            }
        }
    }

    /// Cierre de cada iteración: RMW de una línea completa de 64 B elegida por los registros.
    pub fn commit(&mut self) {
        let line = reduce(self.r[0] ^ self.r[1].rotate_left(32) ^ self.r[2], self.n64) as usize * 64;
        for i in 0..8 {
            let old = self.ld64(line + 8 * i);
            self.st64(line + 8 * i, old ^ self.r[i]);
            self.r[i] = self.r[i].wrapping_add(old);
        }
    }

    pub fn finish(&self, seed: &[u8; 32], tail: &[u8; 64]) -> [u8; 32] {
        let mut regs = [0u8; 192];
        for i in 0..8 {
            regs[8 * i..8 * i + 8].copy_from_slice(&self.r[i].to_le_bytes());
            regs[64 + 16 * i..64 + 16 * i + 16].copy_from_slice(&v2b(self.v[i]));
        }
        sha256_cat(&[b"ARMAX-VM-v0", seed, &regs, tail])
    }
}

/// Un intento de PoW. `scratch.len()` debe ser exactamente `p.scratch_bytes`.
///
/// Cuesta O(scratch_bytes) por intento (relleno secuencial): es lo que fija la
/// tasa real por hilo y el coste de verificar un bloque.
pub fn pow_hash<B: Aes>(p: &Params, table: &OpTable, input: &[u8], scratch: &mut [u8]) -> [u8; 32] {
    p.validate().expect("Params inválidos");
    assert_eq!(scratch.len(), p.scratch_bytes, "scratchpad con tamaño distinto de Params");
    let seed = sha256(input);
    let prog = gen_program::<B>(&seed, p.prog_len);
    AesGen::<B>::new(&seed, DOM_SCRATCH).fill(scratch);
    let mut tail = [0u8; 64];
    tail.copy_from_slice(&scratch[scratch.len() - 64..]);
    let mut vm = Vm::<B>::new(&seed, scratch);
    for _ in 0..p.iterations {
        vm.exec(&prog, table);
        vm.commit();
    }
    vm.finish(&seed, &tail)
}
