package org.armax.app

import android.content.Context

/** Ajustes del nodo. Se aplican al (re)iniciar el nodo. */
data class Settings(
    /** "fast" (red de pruebas con PoW reducido) o "devnet" (parámetros de consenso). */
    val network: String = "fast",
    /** Nodos a los que conectar: "IP:PUERTO,IP:PUERTO". */
    val connect: String = "",
    /** Claves fijadas: "IP:PUERTO=CLAVE64HEX,…". */
    val pin: String = "",
    val mine: Boolean = true,
    val pool: Boolean = true,
    val anyPower: Boolean = false,
    val minBattery: Int = 15,
    val mineWithScreenOn: Boolean = false,
    val threads: Int = 1,
)

class SettingsStore(context: Context) {
    private val appContext = context.applicationContext
    private val prefs = context.applicationContext.getSharedPreferences("armax_settings", Context.MODE_PRIVATE)

    fun load(): Settings {
        // nodos públicos de fábrica (res/values/seeds.xml); lo que el usuario guarde en Ajustes los sustituye
        val d = Settings(
            connect = appContext.getString(R.string.default_connect),
            pin = appContext.getString(R.string.default_pin),
        )
        return Settings(
            network = prefs.getString("network", d.network) ?: d.network,
            connect = prefs.getString("connect", d.connect) ?: d.connect,
            pin = prefs.getString("pin", d.pin) ?: d.pin,
            mine = prefs.getBoolean("mine", d.mine),
            pool = prefs.getBoolean("pool", d.pool),
            anyPower = prefs.getBoolean("anyPower", d.anyPower),
            minBattery = prefs.getInt("minBattery", d.minBattery),
            mineWithScreenOn = prefs.getBoolean("mineWithScreenOn", d.mineWithScreenOn),
            threads = prefs.getInt("threads", d.threads),
        )
    }

    fun save(s: Settings) {
        prefs.edit()
            .putString("network", s.network)
            .putString("connect", s.connect.trim())
            .putString("pin", s.pin.trim())
            .putBoolean("mine", s.mine)
            .putBoolean("pool", s.pool)
            .putBoolean("anyPower", s.anyPower)
            .putInt("minBattery", s.minBattery)
            .putBoolean("mineWithScreenOn", s.mineWithScreenOn)
            .putInt("threads", s.threads)
            .apply()
    }
}
