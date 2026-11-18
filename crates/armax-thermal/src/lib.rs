//! `armax-thermal`: gobernador térmico de ARMax.
//!
//! * `governor` — decide cuántos hilos de minado corren según temperatura de batería, cargador,
//!   pantalla y memoria, con histéresis y falla hacia pausar. Lógica pura, probada con simulaciones.
//! * `source`   — lecturas del dispositivo (sysfs, Termux:API); la app Android implementará `SensorSource`.

pub mod governor;
pub mod source;

pub use governor::{Decision, Governor, Reason, Sensors, ThermalConfig};
pub use source::{AutoSource, SensorSource, SysfsSource, TermuxApiSource};
