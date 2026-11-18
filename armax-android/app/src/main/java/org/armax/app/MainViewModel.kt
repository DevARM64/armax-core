package org.armax.app

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlin.concurrent.thread

enum class Phase { Loading, Onboarding, Backup, Home }

class MainViewModel(app: Application) : AndroidViewModel(app) {
    private val ctx = app.applicationContext
    private val store = SettingsStore(ctx)

    private val _phase = MutableStateFlow(Phase.Loading)
    val phase: StateFlow<Phase> = _phase

    /** Frase de 12 palabras: solo existe aquí entre crear la cartera y confirmar el respaldo. */
    private val _mnemonic = MutableStateFlow<String?>(null)
    val mnemonic: StateFlow<String?> = _mnemonic

    private val _address = MutableStateFlow<String?>(null)
    val address: StateFlow<String?> = _address

    private val _settings = MutableStateFlow(store.load())
    val settings: StateFlow<Settings> = _settings

    private val _busy = MutableStateFlow(false)
    val busy: StateFlow<Boolean> = _busy

    /** Mensaje para mostrar en un diálogo (error o confirmación). */
    private val _message = MutableStateFlow<String?>(null)
    val message: StateFlow<String?> = _message

    private var pendingSealed: ByteArray? = null

    init {
        thread { loadWallet() }
    }

    fun dismissMessage() {
        _message.value = null
    }

    private fun loadWallet() {
        val f = NodeService.sealedFile(ctx)
        if (!f.exists()) {
            _phase.value = Phase.Onboarding
            return
        }
        try {
            _address.value = Armax.walletAddress(KeystoreVault().native(), f.readBytes())
            _phase.value = Phase.Home
        } catch (e: Throwable) {
            // p. ej. la clave del Keystore ya no existe (teléfono restaurado): solo queda restaurar con la frase
            _message.value = ctx.getString(R.string.msg_wallet_open_failed, e.message ?: e.toString())
            _phase.value = Phase.Onboarding
        }
    }

    fun createWallet() {
        if (_busy.value) return
        _busy.value = true
        thread {
            try {
                val w = Armax.createWallet(KeystoreVault().native())
                pendingSealed = w.sealed
                _mnemonic.value = w.mnemonic
                _phase.value = Phase.Backup
            } catch (e: Throwable) {
                _message.value = e.message ?: e.toString()
            } finally {
                _busy.value = false
            }
        }
    }

    /** La persona confirmó que anotó la frase: recién ahora se guarda la cartera en el teléfono. */
    fun confirmBackup() {
        val sealed = pendingSealed ?: return
        thread {
            try {
                NodeService.sealedFile(ctx).writeBytes(sealed)
                _address.value = Armax.walletAddress(KeystoreVault().native(), sealed)
                pendingSealed = null
                _mnemonic.value = null
                _phase.value = Phase.Home
            } catch (e: Throwable) {
                _message.value = e.message ?: e.toString()
            }
        }
    }

    fun restoreWallet(phrase: String) {
        if (_busy.value) return
        _busy.value = true
        thread {
            try {
                val vault = KeystoreVault().native()
                val sealed = Armax.restoreWallet(vault, phrase)
                NodeService.sealedFile(ctx).writeBytes(sealed)
                _address.value = Armax.walletAddress(vault, sealed)
                _phase.value = Phase.Home
            } catch (e: Throwable) {
                _message.value = e.message ?: e.toString()
            } finally {
                _busy.value = false
            }
        }
    }

    private val _history = MutableStateFlow<List<HistoryEntry>>(emptyList())
    val history: StateFlow<List<HistoryEntry>> = _history

    @Volatile
    private var historyBusy = false

    /** Relee el historial del nodo (si está en marcha). No se solapan dos lecturas. */
    fun refreshHistory() {
        if (historyBusy) return
        historyBusy = true
        thread {
            try {
                NodeState.withHandle { h -> Armax.history(h, 100) }?.let { _history.value = it }
            } catch (e: Throwable) {
                // se reintenta en la próxima lectura
            } finally {
                historyBusy = false
            }
        }
    }

    fun startNode() {
        NodeState.setError(null)
        NodeService.start(ctx)
    }

    fun stopNode() {
        NodeService.stop(ctx)
    }

    fun saveSettings(s: Settings) {
        store.save(s)
        _settings.value = s
        _message.value = ctx.getString(if (NodeState.running.value) R.string.msg_saved_restart else R.string.msg_saved)
    }

    fun send(to: String, amountText: String, feeText: String) {
        if (_busy.value) return
        val amount = Armax.parseAmount(amountText)
        if (amount == null || amount <= 0) {
            _message.value = ctx.getString(R.string.msg_bad_amount)
            return
        }
        val fee = if (feeText.isBlank()) 0L else feeText.trim().toLongOrNull()
        if (fee == null || fee < 0) {
            _message.value = ctx.getString(R.string.msg_bad_fee)
            return
        }
        _busy.value = true
        thread {
            try {
                val txid = NodeState.withHandle { h -> Armax.send(h, to, amount, fee) }
                _message.value = if (txid == null) ctx.getString(R.string.msg_node_not_running) else ctx.getString(R.string.msg_sent, txid)
            } catch (e: Throwable) {
                _message.value = e.message ?: e.toString()
            } finally {
                _busy.value = false
            }
        }
    }
}
