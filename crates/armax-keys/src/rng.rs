//! Entropía del sistema operativo (`/dev/urandom`: Linux, Android, Termux).
//!
//! En la app Android se debe usar `SecureRandom` y pasar los bytes a `Wallet::create_from_entropy`;
//! esta función sirve para pruebas y para herramientas de línea de comandos.

use std::io::Read;

pub fn fill_os_random(buf: &mut [u8]) -> std::io::Result<()> {
    std::fs::File::open("/dev/urandom")?.read_exact(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_different_bytes() {
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        fill_os_random(&mut a).unwrap();
        fill_os_random(&mut b).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }
}
