package org.armax.app

import com.sun.jna.Pointer
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * Estado del nodo compartido entre el servicio (que lo arranca y lo para) y la interfaz.
 * Toda llamada nativa con el manejador pasa por `withHandle`/`stopNode`, que comparten un candado:
 * así la interfaz nunca usa un manejador que el servicio ya liberó.
 */
object NodeState {
    private val lock = Any()
    private var handle: Pointer? = null

    private val _status = MutableStateFlow<NodeStatus?>(null)
    val status: StateFlow<NodeStatus?> = _status

    /** Últimas lecturas de velocidad (H/s), una por segundo, para la gráfica del panel. */
    private val _hashrates = MutableStateFlow<List<Float>>(emptyList())
    val hashrates: StateFlow<List<Float>> = _hashrates

    private val _running = MutableStateFlow(false)
    val running: StateFlow<Boolean> = _running

    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error

    fun setError(msg: String?) {
        _error.value = msg
    }

    fun publish(s: NodeStatus) {
        _status.value = s
        val hr = (s.miner?.hashrate ?: 0.0).toFloat()
        _hashrates.value = (_hashrates.value + hr).takeLast(120)
    }

    fun nodeStarted(h: Pointer) = synchronized(lock) {
        handle = h
        _running.value = true
        _error.value = null
    }

    /** Ejecuta `f` con el manejador, o devuelve null si el nodo no está en marcha. */
    fun <T> withHandle(f: (Pointer) -> T): T? = synchronized(lock) { handle?.let(f) }

    /** Para el nodo (una sola vez) y limpia el estado. */
    fun stopNode() = synchronized(lock) {
        handle?.let { Armax.stop(it) }
        handle = null
        _running.value = false
        _status.value = null
        _hashrates.value = emptyList()
    }
}
