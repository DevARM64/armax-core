//! Conjunto de 160 instrucciones de la VM de ARMax y su mutación por época.
//!
//! Cada instrucción cruda lleva un opcode 0..159. La *semántica* de ese opcode
//! se obtiene de una tabla permutada por época (`OpTable::for_epoch`), de modo
//! que ningún circuito fijo sirve más de una época.
//!
//! Distribución de las 160 semánticas:
//!
//! | familia                                   | n  |
//! |-------------------------------------------|----|
//! | ALU reg-reg (16 ops) / reg-imm (16 ops)   | 32 |
//! | unarias (8) + fusionadas (8)              | 16 |
//! | cargas 64/32 bit, stores, RMW, V-load/store (6 x 8) | 48 |
//! | AES enc/dec (2 x 8)                       | 16 |
//! | ALU vectorial 128 bit                     | 16 |
//! | transferencias escalar<->vector           |  8 |
//! | ramas condicionales hacia delante (6+6+4) | 16 |
//! | cmov                                      |  8 |

use crate::sha256::sha256_cat;

pub const NUM_OPS: usize = 160;
pub const INSTR_BYTES: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AluOp {
    Add,
    Sub,
    RSub,
    Xor,
    And,
    Or,
    AndN,
    Xnor,
    Mul,
    UMulH,
    SMulH,
    Rol,
    Ror,
    Shl,
    Shr,
    Sar,
}

pub const ALU_OPS: [AluOp; 16] = [
    AluOp::Add,
    AluOp::Sub,
    AluOp::RSub,
    AluOp::Xor,
    AluOp::And,
    AluOp::Or,
    AluOp::AndN,
    AluOp::Xnor,
    AluOp::Mul,
    AluOp::UMulH,
    AluOp::SMulH,
    AluOp::Rol,
    AluOp::Ror,
    AluOp::Shl,
    AluOp::Shr,
    AluOp::Sar,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UnOp {
    Neg,
    Not,
    Bswap,
    Clz,
    Ctz,
    Popcnt,
    Rbit,
    Swap32,
}

pub const UN_OPS: [UnOp; 8] = [
    UnOp::Neg,
    UnOp::Not,
    UnOp::Bswap,
    UnOp::Clz,
    UnOp::Ctz,
    UnOp::Popcnt,
    UnOp::Rbit,
    UnOp::Swap32,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VOp {
    Add64,
    Sub64,
    Add32,
    Xor,
    And,
    Or,
    AndN,
    Mul32,
    Rol64,
    Ror64,
    Shl64,
    Shr64,
    Swap,
    Rev8,
    Cnt8,
    Ext,
}

pub const V_OPS: [VOp; 16] = [
    VOp::Add64,
    VOp::Sub64,
    VOp::Add32,
    VOp::Xor,
    VOp::And,
    VOp::Or,
    VOp::AndN,
    VOp::Mul32,
    VOp::Rol64,
    VOp::Ror64,
    VOp::Shl64,
    VOp::Shr64,
    VOp::Swap,
    VOp::Rev8,
    VOp::Cnt8,
    VOp::Ext,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Cond {
    Eq,
    Ne,
    Lt,
    Ge,
    Ltu,
    Geu,
}

pub const CONDS: [Cond; 6] = [Cond::Eq, Cond::Ne, Cond::Lt, Cond::Ge, Cond::Ltu, Cond::Geu];

/// Semántica de una instrucción. Los `u8` son variantes dentro de la familia.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Sem {
    AluRR(AluOp),
    AluRI(AluOp),
    Unary(UnOp),
    Fused(u8),
    Load64(u8),
    Load32(u8),
    Store64(u8),
    Rmw(u8),
    VLoad(u8),
    VStore(u8),
    AesEnc(u8),
    AesDec(u8),
    VAlu(VOp),
    Xfer(u8),
    BranchRR(Cond),
    BranchRI(Cond),
    BitBranch(u8),
    Cmov(u8),
}

const fn build_sem_table() -> [Sem; NUM_OPS] {
    let mut t = [Sem::Fused(0); NUM_OPS];
    let mut i = 0usize;
    let mut k;

    k = 0;
    while k < 16 {
        t[i] = Sem::AluRR(ALU_OPS[k]);
        i += 1;
        k += 1;
    }
    k = 0;
    while k < 16 {
        t[i] = Sem::AluRI(ALU_OPS[k]);
        i += 1;
        k += 1;
    }
    k = 0;
    while k < 8 {
        t[i] = Sem::Unary(UN_OPS[k]);
        i += 1;
        k += 1;
    }
    k = 0;
    while k < 8 {
        t[i] = Sem::Fused(k as u8);
        i += 1;
        k += 1;
    }
    k = 0;
    while k < 8 {
        t[i] = Sem::Load64(k as u8);
        i += 1;
        k += 1;
    }
    k = 0;
    while k < 8 {
        t[i] = Sem::Load32(k as u8);
        i += 1;
        k += 1;
    }
    k = 0;
    while k < 8 {
        t[i] = Sem::Store64(k as u8);
        i += 1;
        k += 1;
    }
    k = 0;
    while k < 8 {
        t[i] = Sem::Rmw(k as u8);
        i += 1;
        k += 1;
    }
    k = 0;
    while k < 8 {
        t[i] = Sem::VLoad(k as u8);
        i += 1;
        k += 1;
    }
    k = 0;
    while k < 8 {
        t[i] = Sem::VStore(k as u8);
        i += 1;
        k += 1;
    }
    k = 0;
    while k < 8 {
        t[i] = Sem::AesEnc(k as u8);
        i += 1;
        k += 1;
    }
    k = 0;
    while k < 8 {
        t[i] = Sem::AesDec(k as u8);
        i += 1;
        k += 1;
    }
    k = 0;
    while k < 16 {
        t[i] = Sem::VAlu(V_OPS[k]);
        i += 1;
        k += 1;
    }
    k = 0;
    while k < 8 {
        t[i] = Sem::Xfer(k as u8);
        i += 1;
        k += 1;
    }
    k = 0;
    while k < 6 {
        t[i] = Sem::BranchRR(CONDS[k]);
        i += 1;
        k += 1;
    }
    k = 0;
    while k < 6 {
        t[i] = Sem::BranchRI(CONDS[k]);
        i += 1;
        k += 1;
    }
    k = 0;
    while k < 4 {
        t[i] = Sem::BitBranch(k as u8);
        i += 1;
        k += 1;
    }
    k = 0;
    while k < 8 {
        t[i] = Sem::Cmov(k as u8);
        i += 1;
        k += 1;
    }
    assert!(i == NUM_OPS);
    t
}

/// Las 160 semánticas en su orden canónico (época "identidad").
pub static SEM_TABLE: [Sem; NUM_OPS] = build_sem_table();

/// Tabla opcode -> semántica para una época concreta.
#[derive(Clone)]
pub struct OpTable {
    pub sem: [Sem; NUM_OPS],
    perm: [u8; NUM_OPS],
}

impl OpTable {
    /// Época 0 / pruebas: opcode `i` = semántica canónica `i`.
    pub fn identity() -> Self {
        let mut perm = [0u8; NUM_OPS];
        for (i, p) in perm.iter_mut().enumerate() {
            *p = i as u8;
        }
        Self { sem: SEM_TABLE, perm }
    }

    /// Permutación determinista (Fisher-Yates) derivada de la semilla de época,
    /// p. ej. el hash del bloque de frontera de época.
    pub fn for_epoch(epoch_seed: &[u8; 32]) -> Self {
        let mut perm = [0u8; NUM_OPS];
        for (i, p) in perm.iter_mut().enumerate() {
            *p = i as u8;
        }
        let mut ctr = 0u32;
        let mut buf = [0u8; 32];
        let mut pos = 32usize;
        let mut next_u32 = || {
            if pos >= 32 {
                buf = sha256_cat(&[b"ARMAX-OPTABLE-v0", epoch_seed, &ctr.to_le_bytes()]);
                ctr += 1;
                pos = 0;
            }
            let v = u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
            pos += 4;
            v
        };
        for i in (1..NUM_OPS).rev() {
            let r = next_u32();
            let j = ((r as u64 * (i as u64 + 1)) >> 32) as usize;
            perm.swap(i, j);
        }
        let mut sem = SEM_TABLE;
        for (i, s) in sem.iter_mut().enumerate() {
            *s = SEM_TABLE[perm[i] as usize];
        }
        Self { sem, perm }
    }

    pub fn permutation(&self) -> &[u8; NUM_OPS] {
        &self.perm
    }
}

/// Instrucción decodificada (8 bytes en el flujo).
///
/// Formato: `[op_lo, op_hi, dst(3b)|src(3b)<<3, aux, imm32 LE]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Instr {
    pub op: u8,
    pub dst: u8,
    pub src: u8,
    pub aux: u8,
    pub imm: u32,
}

impl Instr {
    pub fn decode(b: &[u8; INSTR_BYTES]) -> Self {
        let raw = u16::from_le_bytes([b[0], b[1]]) as u32;
        Self {
            // reduce 16 bits a 0..159 con sesgo despreciable (<0.25 %)
            op: ((raw * NUM_OPS as u32) >> 16) as u8,
            dst: b[2] & 7,
            src: (b[2] >> 3) & 7,
            aux: b[3],
            imm: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn exactly_160_distinct_semantics() {
        let set: HashSet<Sem> = SEM_TABLE.iter().copied().collect();
        assert_eq!(set.len(), NUM_OPS);
    }

    #[test]
    fn epoch_table_is_a_permutation() {
        for n in 0..8u8 {
            let t = OpTable::for_epoch(&[n; 32]);
            let set: HashSet<u8> = t.permutation().iter().copied().collect();
            assert_eq!(set.len(), NUM_OPS);
            let sems: HashSet<Sem> = t.sem.iter().copied().collect();
            assert_eq!(sems.len(), NUM_OPS);
        }
    }

    #[test]
    fn epochs_differ_and_are_deterministic() {
        let a = OpTable::for_epoch(&[1u8; 32]);
        let b = OpTable::for_epoch(&[2u8; 32]);
        let a2 = OpTable::for_epoch(&[1u8; 32]);
        assert_ne!(a.permutation(), b.permutation());
        assert_eq!(a.permutation(), a2.permutation());
        assert_ne!(a.permutation(), OpTable::identity().permutation());
    }

    #[test]
    fn opcode_reduction_covers_range() {
        let mut seen = [false; NUM_OPS];
        for raw in 0..=u16::MAX {
            let i = Instr::decode(&[raw as u8, (raw >> 8) as u8, 0, 0, 0, 0, 0, 0]);
            assert!((i.op as usize) < NUM_OPS);
            seen[i.op as usize] = true;
        }
        assert!(seen.iter().all(|&x| x));
    }
}
