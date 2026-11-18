//! Gobernador térmico: decide cuántos hilos de minado pueden correr ahora.
//!
//! Es lógica pura (sin E/S ni reloj propio): recibe lecturas (`Sensors`) y devuelve una
//! decisión (`Decision`). Así se prueba con simulaciones y sirve igual desde Termux, desde un
//! servicio de Android (vía JNI/`BatteryManager`) o desde tests.
//!
//! # Política por defecto (calibrada con mediciones en un teléfono real)
//! * 2 hilos y teléfono cargando: la batería llegó a 40 °C y el sistema redujo el rendimiento ~15 %.
//! * 1 hilo y teléfono cargando: la batería se mantuvo en 37.0 °C durante 10 minutos.
//!
//! | situación                                     | hilos |
//! |-----------------------------------------------|-------|
//! | batería ≤ 36 °C (y pasó el tiempo de espera)  | 2     |
//! | 36 °C < batería < 39 °C                       | se mantiene el nivel actual (≥ 1) |
//! | batería ≥ 39 °C                               | 1     |
//! | batería ≥ 42 °C                               | 0 (pausa) hasta bajar a ≤ 38 °C |
//!
//! Con esos umbrales, un teléfono cargando se estabiliza en 1 hilo; solo sube a 2 si está
//! realmente fresco, y baja al primer indicio de calor.
//!
//! # Seguridad por defecto (falla hacia pausar)
//! Sin lectura de temperatura, o con una lectura implausible, no se mina (la sonda de pruebas
//! sí lo permitía; un nodo real no debe). Tampoco se mina si no se sabe si está cargando
//! (con `require_charging`), con la pantalla encendida, ni con poca memoria libre.
//!
//! Bajar hilos o pausar es inmediato; subir exige `min_dwell_s` desde el último cambio (salvo
//! el arranque de 0 a 1 hilo), para que no oscile.

/// Lecturas del dispositivo. `None` = desconocido.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Sensors {
    /// Reloj monótono en segundos (solo se usa para diferencias).
    pub now_s: u64,
    /// Temperatura de la batería en °C.
    pub battery_temp_c: Option<f64>,
    /// Conectado a un cargador (cargando, lleno o en protección de carga).
    pub charging: Option<bool>,
    /// Porcentaje de batería (0-100).
    pub battery_pct: Option<u8>,
    /// Pantalla encendida / el usuario está usando el equipo.
    pub screen_on: Option<bool>,
    /// Memoria disponible del sistema (MemAvailable), en MiB.
    pub mem_available_mib: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ThermalConfig {
    pub max_threads: u8,
    /// Solo se sube a más de 1 hilo si la batería está a esta temperatura o menos.
    pub two_threads_below_c: f64,
    /// Al alcanzar esta temperatura se baja a 1 hilo.
    pub one_thread_above_c: f64,
    /// Al alcanzar esta temperatura se pausa por completo.
    pub pause_at_c: f64,
    /// Tras una pausa por calor, se reanuda cuando la batería baja a esta temperatura o menos.
    pub resume_below_c: f64,
    /// Segundos mínimos desde el último cambio antes de poder subir de 1 hilo a más.
    pub min_dwell_s: u64,
    /// Solo minar con el cargador conectado.
    pub require_charging: bool,
    /// Si `require_charging` es falso y no hay cargador: batería mínima para minar.
    pub min_battery_pct_unplugged: u8,
    /// Pausar mientras la pantalla esté encendida.
    pub pause_when_screen_on: bool,
    /// Permitir minar (con 1 hilo) sin lectura de temperatura. Solo para pruebas.
    pub allow_without_temperature: bool,
    pub mem_per_thread_mib: u64,
    /// Memoria que debe quedar libre tras reservar los hilos.
    pub mem_headroom_mib: u64,
}

impl Default for ThermalConfig {
    fn default() -> Self {
        Self {
            max_threads: 2,
            two_threads_below_c: 36.0,
            one_thread_above_c: 39.0,
            pause_at_c: 42.0,
            resume_below_c: 38.0,
            min_dwell_s: 120,
            require_charging: true,
            min_battery_pct_unplugged: 15,
            pause_when_screen_on: true,
            allow_without_temperature: false,
            mem_per_thread_mib: 384,
            mem_headroom_mib: 1024,
        }
    }
}

impl ThermalConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        let temps = [self.two_threads_below_c, self.one_thread_above_c, self.pause_at_c, self.resume_below_c];
        if temps.iter().any(|t| !t.is_finite()) {
            return Err("las temperaturas deben ser números finitos");
        }
        if self.max_threads == 0 {
            return Err("max_threads debe ser ≥ 1");
        }
        if !(self.two_threads_below_c < self.one_thread_above_c && self.one_thread_above_c < self.pause_at_c) {
            return Err("se requiere two_threads_below_c < one_thread_above_c < pause_at_c");
        }
        if self.resume_below_c >= self.pause_at_c {
            return Err("resume_below_c debe ser menor que pause_at_c");
        }
        if self.mem_per_thread_mib == 0 {
            return Err("mem_per_thread_mib debe ser > 0");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// Corriendo con el máximo de hilos permitido.
    Running,
    /// Temperatura y memoria permiten más hilos, pero se sube de a uno tras `min_dwell_s`.
    Ramping,
    /// Corriendo con menos hilos por la temperatura.
    LimitedByTemperature,
    /// Corriendo con menos hilos por falta de memoria.
    LimitedByMemory,
    NoTemperatureSensor,
    NoChargingInfo,
    NotCharging,
    LowBattery,
    ScreenOn,
    /// Pausa: la batería llegó al límite.
    Overheated,
    /// Pausa: enfriando hasta `resume_below_c`.
    Cooling,
    LowMemory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    pub threads: u8,
    pub reason: Reason,
}

pub struct Governor {
    cfg: ThermalConfig,
    level: u8,
    cooling: bool,
    last_change_s: u64,
}

/// Rango de lecturas de batería que se consideran reales.
fn plausible(t: f64) -> bool {
    t.is_finite() && (-20.0..=80.0).contains(&t)
}

impl Governor {
    pub fn new(cfg: ThermalConfig) -> Result<Self, &'static str> {
        cfg.validate()?;
        Ok(Self { cfg, level: 0, cooling: false, last_change_s: 0 })
    }

    /// Hilos que la decisión anterior dejó corriendo.
    pub fn level(&self) -> u8 {
        self.level
    }

    pub fn is_cooling(&self) -> bool {
        self.cooling
    }

    fn set_level(&mut self, new: u8, now: u64) {
        if new != self.level {
            self.level = new;
            self.last_change_s = now;
        }
    }

    fn pause(&mut self, reason: Reason, now: u64) -> Decision {
        self.set_level(0, now);
        Decision { threads: 0, reason }
    }

    pub fn update(&mut self, s: &Sensors) -> Decision {
        let cfg = self.cfg;
        let now = s.now_s;
        let temp = s.battery_temp_c.filter(|t| plausible(*t));

        // 1. paradas duras (inmediatas)
        if temp.is_none() && !cfg.allow_without_temperature {
            return self.pause(Reason::NoTemperatureSensor, now);
        }
        match (cfg.require_charging, s.charging) {
            (true, None) => return self.pause(Reason::NoChargingInfo, now),
            (true, Some(false)) => return self.pause(Reason::NotCharging, now),
            (false, Some(false)) => match s.battery_pct {
                Some(p) if p >= cfg.min_battery_pct_unplugged => {}
                _ => return self.pause(Reason::LowBattery, now),
            },
            _ => {}
        }
        if cfg.pause_when_screen_on && s.screen_on == Some(true) {
            return self.pause(Reason::ScreenOn, now);
        }
        match temp {
            Some(t) if t >= cfg.pause_at_c => {
                self.cooling = true;
                return self.pause(Reason::Overheated, now);
            }
            Some(t) if self.cooling => {
                if t <= cfg.resume_below_c {
                    self.cooling = false;
                } else {
                    return self.pause(Reason::Cooling, now);
                }
            }
            None if self.cooling => return self.pause(Reason::Cooling, now),
            _ => {}
        }

        // 2. tope por temperatura, con histéresis
        let max = cfg.max_threads;
        let mut cap = match temp {
            Some(t) if t >= cfg.one_thread_above_c => 1.min(max),
            Some(t) if t <= cfg.two_threads_below_c => max,
            Some(_) => self.level.clamp(1, max), // banda intermedia: mantener
            None => 1.min(max),                  // sin temperatura (solo modo de pruebas): prudente
        };
        let mut reason = if cap < max { Reason::LimitedByTemperature } else { Reason::Running };

        // 3. tope por memoria. `mem_available` ya descuenta lo que usan los hilos activos,
        //    así que el total posible es lo que ya corre más lo que cabe adicionalmente.
        if let Some(avail) = s.mem_available_mib {
            let extra = avail.saturating_sub(cfg.mem_headroom_mib) / cfg.mem_per_thread_mib;
            let total = (self.level as u64 + extra).min(u8::MAX as u64) as u8;
            if total == 0 {
                return self.pause(Reason::LowMemory, now);
            }
            if total < cap {
                cap = total;
                reason = Reason::LimitedByMemory;
            }
        }

        // 4. aplicar: bajar es inmediato; siempre se arranca con 1 hilo, y subir de ahí exige
        //    que pasen `min_dwell_s` desde el último cambio
        let mut target = cap;
        if target > self.level {
            if self.level == 0 {
                target = target.min(1);
            } else if now.saturating_sub(self.last_change_s) < cfg.min_dwell_s {
                target = self.level;
            }
        }
        if target < max && reason == Reason::Running {
            reason = Reason::Ramping;
        }
        self.set_level(target, now);
        Decision { threads: target, reason }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sens(now: u64, temp: f64) -> Sensors {
        Sensors {
            now_s: now,
            battery_temp_c: Some(temp),
            charging: Some(true),
            battery_pct: Some(80),
            screen_on: Some(false),
            mem_available_mib: Some(4000),
        }
    }

    fn gov() -> Governor {
        Governor::new(ThermalConfig::default()).unwrap()
    }

    #[test]
    fn default_config_is_valid_and_bad_ones_are_rejected() {
        assert!(ThermalConfig::default().validate().is_ok());
        let c = ThermalConfig { two_threads_below_c: 40.0, ..Default::default() };
        assert!(c.validate().is_err());
        let c = ThermalConfig { max_threads: 0, ..Default::default() };
        assert!(c.validate().is_err());
        let c = ThermalConfig { pause_at_c: f64::NAN, ..Default::default() };
        assert!(c.validate().is_err());
        let c = ThermalConfig { resume_below_c: 45.0, ..Default::default() };
        assert!(c.validate().is_err());
    }

    #[test]
    fn pauses_when_not_charging_or_unknown() {
        let mut g = gov();
        let mut s = sens(0, 30.0);
        s.charging = Some(false);
        assert_eq!(g.update(&s), Decision { threads: 0, reason: Reason::NotCharging });
        s.charging = None;
        assert_eq!(g.update(&s), Decision { threads: 0, reason: Reason::NoChargingInfo });
    }

    #[test]
    fn unplugged_mode_needs_enough_battery() {
        let cfg = ThermalConfig { require_charging: false, ..Default::default() };
        let mut g = Governor::new(cfg).unwrap();
        let mut s = sens(0, 30.0);
        s.charging = Some(false);
        s.battery_pct = Some(60);
        assert_eq!(g.update(&s).threads, 1);
        s.battery_pct = Some(15); // el mínimo por defecto es 15 %: con 15 se mina
        assert_eq!(g.update(&s).threads, 1);
        s.battery_pct = Some(14);
        assert_eq!(g.update(&s), Decision { threads: 0, reason: Reason::LowBattery });
        s.battery_pct = None;
        assert_eq!(g.update(&s), Decision { threads: 0, reason: Reason::LowBattery });
    }

    #[test]
    fn fails_safe_without_a_usable_temperature() {
        let mut g = gov();
        let mut s = sens(0, 30.0);
        s.battery_temp_c = None;
        assert_eq!(g.update(&s), Decision { threads: 0, reason: Reason::NoTemperatureSensor });
        // lectura implausible (como el 93.3 °C estancado que vimos en una zona térmica)
        s.battery_temp_c = Some(93.3);
        assert_eq!(g.update(&s), Decision { threads: 0, reason: Reason::NoTemperatureSensor });
        s.battery_temp_c = Some(f64::NAN);
        assert_eq!(g.update(&s).threads, 0);
        // en modo de pruebas se permite, con 1 hilo
        let cfg = ThermalConfig { allow_without_temperature: true, ..Default::default() };
        let mut g = Governor::new(cfg).unwrap();
        s.battery_temp_c = None;
        assert_eq!(g.update(&s).threads, 1);
    }

    #[test]
    fn starts_with_one_thread_then_two_after_dwell() {
        let mut g = gov();
        assert_eq!(g.update(&sens(0, 30.0)), Decision { threads: 1, reason: Reason::Ramping });
        assert_eq!(g.update(&sens(119, 30.0)).threads, 1);
        assert_eq!(g.update(&sens(120, 30.0)), Decision { threads: 2, reason: Reason::Running });
    }

    #[test]
    fn hysteresis_band_holds_the_current_level() {
        let mut g = gov();
        g.update(&sens(0, 30.0));
        g.update(&sens(200, 30.0)); // -> 2 hilos
        assert_eq!(g.level(), 2);
        assert_eq!(g.update(&sens(210, 37.5)).threads, 2); // banda 36-39: se mantiene
        assert_eq!(g.update(&sens(220, 38.9)).threads, 2);
        assert_eq!(g.update(&sens(230, 39.0)).threads, 1); // baja de inmediato
        // aunque se enfríe a la banda, no vuelve a 2 hasta ≤ 36 °C
        assert_eq!(g.update(&sens(240, 37.0)).threads, 1);
        assert_eq!(g.update(&sens(500, 37.0)).threads, 1);
        // y al llegar a ≤ 36 °C, ya pasado el tiempo de espera, sube
        assert_eq!(g.update(&sens(510, 36.0)).threads, 2);
    }

    #[test]
    fn dwell_blocks_a_quick_return_to_two() {
        let mut g = gov();
        g.update(&sens(0, 30.0));
        g.update(&sens(200, 30.0)); // 2 hilos
        g.update(&sens(210, 39.5)); // baja a 1 en t=210
        assert_eq!(g.update(&sens(250, 30.0)).threads, 1); // fresco, pero aún no pasó el tiempo
        assert_eq!(g.update(&sens(330, 30.0)).threads, 2); // 120 s después
    }

    #[test]
    fn overheating_pauses_and_resumes_only_when_cool_with_one_thread() {
        let mut g = gov();
        g.update(&sens(0, 30.0));
        g.update(&sens(200, 30.0)); // 2 hilos
        assert_eq!(g.update(&sens(210, 42.0)), Decision { threads: 0, reason: Reason::Overheated });
        assert!(g.is_cooling());
        assert_eq!(g.update(&sens(220, 40.0)), Decision { threads: 0, reason: Reason::Cooling });
        assert_eq!(g.update(&sens(230, 38.5)), Decision { threads: 0, reason: Reason::Cooling });
        let d = g.update(&sens(240, 38.0));
        assert_eq!(d.threads, 1);
        assert!(!g.is_cooling());
        // no salta a 2 hilos aunque esté fresco: primero el tiempo de espera
        assert_eq!(g.update(&sens(250, 30.0)).threads, 1);
    }

    #[test]
    fn screen_on_pauses_and_off_resumes() {
        let mut g = gov();
        let mut s = sens(0, 30.0);
        s.screen_on = Some(true);
        assert_eq!(g.update(&s), Decision { threads: 0, reason: Reason::ScreenOn });
        s.now_s = 5;
        s.screen_on = Some(false);
        assert_eq!(g.update(&s).threads, 1);
        // pantalla desconocida: no pausa
        s.screen_on = None;
        s.now_s = 10;
        assert_eq!(g.update(&s).threads, 1);
    }

    #[test]
    fn memory_limits_threads_and_pauses_when_none_fit() {
        let mut g = gov();
        let mut s = sens(0, 30.0);
        s.mem_available_mib = Some(1000); // < headroom de 1024
        assert_eq!(g.update(&s), Decision { threads: 0, reason: Reason::LowMemory });
        s.now_s = 1;
        s.mem_available_mib = Some(1500); // (1500-1024)/384 = 1 hilo extra
        assert_eq!(g.update(&s).threads, 1);

        // con 2 hilos ya corriendo, la memoria libre ya descuenta los suyos
        let mut g = gov();
        g.update(&sens(0, 30.0));
        let mut s = sens(200, 30.0);
        s.mem_available_mib = Some(2000);
        assert_eq!(g.update(&s).threads, 2);
        s.now_s = 210;
        s.mem_available_mib = Some(1100); // quedan 76 MiB utilizables: 0 extra, pero los 2 ya corren
        let d = g.update(&s);
        assert_eq!(d.threads, 2);
        // si la memoria cae por debajo de lo que ya usan, se recorta al total posible
        s.now_s = 220;
        s.mem_available_mib = Some(0);
        assert_eq!(g.update(&s).threads, 2); // total = nivel actual (2) + 0: no inventa hilos nuevos
    }

    #[test]
    fn max_threads_one_never_uses_two() {
        let cfg = ThermalConfig { max_threads: 1, ..Default::default() };
        let mut g = Governor::new(cfg).unwrap();
        for t in 0..20 {
            assert!(g.update(&sens(t * 100, 30.0)).threads <= 1);
        }
    }

    // ---- simulaciones con un modelo térmico simple ------------------------------------------

    /// Batería que tiende a `teq[hilos]` con constante de tiempo `tau`.
    /// Calibrado con las mediciones (cargando): 1 hilo ⇒ 37 °C estable; 2 hilos ⇒ ~40-41 °C.
    struct Sim {
        t: f64,
        teq: [f64; 3],
        tau: f64,
    }

    struct Outcome {
        max_temp: f64,
        changes: usize,
        paused_frac: f64,
        two_frac: f64,
        final_level: u8,
    }

    fn run(mut sim: Sim, cfg: ThermalConfig, hours: u64) -> Outcome {
        let mut g = Governor::new(cfg).unwrap();
        let (dt, steps) = (10u64, hours * 360);
        let (mut max_temp, mut changes, mut paused, mut two, mut last) = (sim.t, 0usize, 0u64, 0u64, 0u8);
        for i in 0..steps {
            let d = g.update(&sens(i * dt, sim.t));
            if d.threads != last {
                changes += 1;
                last = d.threads;
            }
            paused += (d.threads == 0) as u64;
            two += (d.threads == 2) as u64;
            let target = sim.teq[d.threads as usize];
            sim.t += (target - sim.t) * dt as f64 / sim.tau;
            max_temp = max_temp.max(sim.t);
        }
        Outcome {
            max_temp,
            changes,
            paused_frac: paused as f64 / steps as f64,
            two_frac: two as f64 / steps as f64,
            final_level: g.level(),
        }
    }

    #[test]
    fn simulation_phone_like_the_measured_one_settles_on_one_thread() {
        // inactivo 34 °C, 1 hilo 37 °C, 2 hilos 41.5 °C (equilibrios cargando)
        let o = run(Sim { t: 34.0, teq: [34.0, 37.0, 41.5], tau: 150.0 }, ThermalConfig::default(), 3);
        assert!(o.max_temp < 40.0, "máx {}", o.max_temp); // nunca roza el límite de 42
        assert_eq!(o.final_level, 1);
        assert!(o.changes <= 4, "oscila: {} cambios", o.changes);
        assert!(o.two_frac < 0.1, "pasa demasiado tiempo con 2 hilos: {}", o.two_frac);
    }

    #[test]
    fn simulation_cool_environment_keeps_two_threads() {
        // un teléfono que con 2 hilos solo llega a 35 °C puede usar 2 hilos todo el tiempo
        let o = run(Sim { t: 30.0, teq: [30.0, 32.0, 35.0], tau: 150.0 }, ThermalConfig::default(), 3);
        assert_eq!(o.final_level, 2);
        assert!(o.two_frac > 0.9);
        assert_eq!(o.paused_frac, 0.0);
    }

    #[test]
    fn simulation_hot_environment_duty_cycles_below_the_limit() {
        // ambiente caluroso: aun con 1 hilo el equilibrio (43 °C) supera el límite
        let o = run(Sim { t: 36.0, teq: [36.0, 43.0, 47.0], tau: 150.0 }, ThermalConfig::default(), 4);
        assert!(o.max_temp < 42.6, "máx {}", o.max_temp); // sobrepasa el umbral a lo sumo por el paso de muestreo
        assert!(o.paused_frac > 0.1 && o.paused_frac < 0.9, "pausa {}", o.paused_frac);
        assert!(o.changes >= 2);
    }
}
