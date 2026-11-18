//! `armax-net`: red P2P de ARMax.
//!
//! * `codec`: mensajes y tramas (estricto, acotado).
//! * `node`: máquina de estados del nodo, **sin E/S**: recibe eventos y devuelve acciones.
//!   Así se prueba de forma determinista (redes simuladas en memoria) y el mismo código sirve
//!   con cualquier transporte.
//! * `secure`: canal cifrado (X25519 + ChaCha20-Poly1305) que envuelve cada conexión TCP.
//! * `tcp`: transporte con `std::net` e hilos.

pub mod codec;
pub mod node;
pub mod secure;
pub mod tcp;
