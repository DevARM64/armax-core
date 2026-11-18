//! Verificación del PoW desacoplada de la cadena.
//!
//! La cadena no ejecuta la VM directamente: pide a un `PowCheck` que valide la cabecera con la
//! semilla de época que ella calcula. Así los tests de la cadena corren sin reservar 384 MiB,
//! y el nodo real usa `VmPow`.

use core::marker::PhantomData;

use armax_pow::consensus::op_table_for_seed;
use armax_pow::validate::{verify_pow, verify_pow_at};
use armax_pow::{BlockHeader, HeaderError, U256};
use armax_vm::{Aes, MemError, Params, Scratchpad};

pub trait PowCheck {
    fn check(&mut self, header: &BlockHeader, epoch_seed: &[u8; 32]) -> Result<(), HeaderError>;
}

/// Verificador real: ejecuta la VM con el scratchpad completo (reutilizado entre llamadas).
pub struct VmPow<B: Aes> {
    params: Params,
    scratch: Scratchpad,
    _b: PhantomData<B>,
}

impl<B: Aes> VmPow<B> {
    /// Reserva el scratchpad (`params.scratch_bytes`). Falla sin abortar si no hay memoria.
    pub fn new(params: Params) -> Result<Self, MemError> {
        let scratch = Scratchpad::new(params.scratch_bytes)?;
        Ok(Self { params, scratch, _b: PhantomData })
    }
}

impl<B: Aes> PowCheck for VmPow<B> {
    fn check(&mut self, header: &BlockHeader, epoch_seed: &[u8; 32]) -> Result<(), HeaderError> {
        let table = op_table_for_seed(epoch_seed);
        verify_pow::<B>(header, &self.params, &table, self.scratch.as_mut_slice()).map(|_| ())
    }
}

/// Verificación del PoW de un share: la misma VM, contra un umbral más fácil que el de la cabecera.
/// Devuelve el digest si cumple `target`: quien llama lo compara con el target del bloque para
/// saber si el share es además un bloque válido (sin ejecutar la VM otra vez).
pub trait SharePowCheck {
    fn check_at(&mut self, header: &BlockHeader, epoch_seed: &[u8; 32], target: &U256) -> Result<[u8; 32], HeaderError>;
}

impl<B: Aes> SharePowCheck for VmPow<B> {
    fn check_at(&mut self, header: &BlockHeader, epoch_seed: &[u8; 32], target: &U256) -> Result<[u8; 32], HeaderError> {
        let table = op_table_for_seed(epoch_seed);
        verify_pow_at::<B>(header, target, &self.params, &table, self.scratch.as_mut_slice())
    }
}

/// Lo que necesita un nodo: validar bloques y también shares con la misma VM (un solo scratchpad).
pub trait FullPow: PowCheck + SharePowCheck {}
impl<T: PowCheck + SharePowCheck> FullPow for T {}

/// **Solo tests.** Acepta cualquier share y devuelve un digest de ceros (cumple todo target).
impl SharePowCheck for SkipPow {
    fn check_at(&mut self, _: &BlockHeader, _: &[u8; 32], _: &U256) -> Result<[u8; 32], HeaderError> {
        Ok([0u8; 32])
    }
}

/// Acepta cualquier PoW. **Solo para tests y herramientas; nunca en un nodo.**
pub struct SkipPow;

impl PowCheck for SkipPow {
    fn check(&mut self, _: &BlockHeader, _: &[u8; 32]) -> Result<(), HeaderError> {
        Ok(())
    }
}
