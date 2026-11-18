// Capa cómoda sobre la ABI C: convierte códigos de error en excepciones y el JSON de estado en clases.
package org.armax.app

import android.content.Context
import com.sun.jna.Pointer
import com.sun.jna.ptr.LongByReference
import com.sun.jna.ptr.PointerByReference
import org.json.JSONArray
import org.json.JSONObject
import java.util.Arrays

const val UNITS_PER_ARM = 100_000_000L

class ArmaxException(message: String) : Exception(message)

data class MinerStatus(
    val threads: Int,
    val reason: String,
    val hashrate: Double,
    val blocks: Long,
    val sharesFound: Long,
    val batteryTempC: Double?,
)

data class PoolStatus(val shares: Long, val orphans: Long, val myPpm: Long?)

data class NodeStatus(
    val height: Long,
    val tip: String,
    val peers: Int,
    val readyPeers: Int,
    val mempool: Int,
    val syncing: Boolean,
    val balance: Long?,
    val spendable: Long?,
    val address: String?,
    val network: String,
    val miner: MinerStatus?,
    val pool: PoolStatus?,
)

/** Un movimiento de la cartera. `kind`: mined, received, sent o internal. `height == null` = pendiente. */
data class HistoryEntry(
    val kind: String,
    val amount: Long,
    val height: Long?,
    val timestamp: Long?,
    val txid: String?,
    val counterparty: String?,
    val confirmations: Long,
    val maturesIn: Long,
    /** Comisión pagada, solo en envíos hechos desde este nodo. */
    val fee: Long?,
)

data class NewWallet(val mnemonic: String, val sealed: ByteArray)

object Armax {
    private val lib: ArmaxLib get() = ArmaxLib.INSTANCE

    /** Texto UTF-8 terminado en NUL dentro de un búfer. */
    private fun cString(buf: ByteArray): String {
        var n = 0
        while (n < buf.size && buf[n] != 0.toByte()) n++
        return String(buf, 0, n, Charsets.UTF_8)
    }

    private var appCtx: Context? = null

    /** Lo llama `ArmaxApplication`: sin contexto no hay textos localizados. */
    fun init(ctx: Context) {
        appCtx = ctx.applicationContext
    }

    private fun str(id: Int, vararg args: Any): String = appCtx?.getString(id, *args) ?: ""

    fun lastError(): String {
        val b = ByteArray(1024)
        return if (lib.armax_last_error(b, b.size.toLong()) >= 0) cString(b) else str(R.string.native_unknown)
    }

    private val insufficient = Regex("""insuficiente: ([0-9.]+) ARM .* para ([0-9.]+) \+ comisión ([0-9.]+)""")

    /** El núcleo escribe sus mensajes en español: los conocidos se traducen al idioma del teléfono. */
    fun localizeNative(d: String): String {
        insufficient.find(d)?.let { m ->
            return str(R.string.native_insufficient, m.groupValues[1], m.groupValues[2], m.groupValues[3])
        }
        return when {
            d.startsWith("dirección inválida") -> str(R.string.native_bad_address)
            d.startsWith("la cantidad debe ser mayor") -> str(R.string.native_zero_amount)
            d.startsWith("el nodo no responde") -> str(R.string.native_node_unresponsive)
            d.startsWith("no hay cartera") -> str(R.string.native_no_wallet)
            d.startsWith("el mempool la rechazó") -> str(R.string.native_mempool_rejected, d.substringAfter(": ", d))
            d.startsWith("frase inválida") -> str(R.string.native_bad_phrase)
            d.startsWith("no se pudo desbloquear la cartera") -> str(R.string.native_wallet_unlock)
            else -> d
        }
    }

    private fun fail(whatRes: Int, code: Int): Nothing =
        throw ArmaxException(str(R.string.err_format, str(whatRes), localizeNative(lastError()), code))

    fun version(): String {
        val b = ByteArray(64)
        return if (lib.armax_version(b, b.size.toLong()) >= 0) cString(b) else "?"
    }

    fun createWallet(vault: ArmaxVault): NewWallet {
        val mn = ByteArray(512)
        val sealed = ByteArray(4096)
        val len = LongByReference()
        val rc = lib.armax_wallet_create(vault, mn, mn.size.toLong(), sealed, sealed.size.toLong(), len)
        if (rc < 0) fail(R.string.err_create_wallet, rc)
        val result = NewWallet(cString(mn), sealed.copyOf(len.value.toInt()))
        Arrays.fill(mn, 0)
        Arrays.fill(sealed, 0)
        return result
    }

    fun restoreWallet(vault: ArmaxVault, phrase: String): ByteArray {
        val sealed = ByteArray(4096)
        val len = LongByReference()
        val rc = lib.armax_wallet_restore(vault, phrase.trim().lowercase().replace(Regex("\\s+"), " "), sealed, sealed.size.toLong(), len)
        if (rc < 0) fail(R.string.err_restore_wallet, rc)
        val result = sealed.copyOf(len.value.toInt())
        Arrays.fill(sealed, 0)
        return result
    }

    fun walletAddress(vault: ArmaxVault, sealed: ByteArray): String {
        val out = ByteArray(256)
        val rc = lib.armax_wallet_address(vault, sealed, sealed.size.toLong(), out, out.size.toLong())
        if (rc < 0) fail(R.string.err_read_address, rc)
        return cString(out)
    }

    fun startNode(configJson: String, vault: ArmaxVault, sealed: ByteArray): Pointer {
        val h = PointerByReference()
        val rc = lib.armax_node_start(configJson, vault, sealed, sealed.size.toLong(), h)
        if (rc < 0) fail(R.string.err_start_node, rc)
        return h.value ?: throw ArmaxException(str(R.string.err_no_handle))
    }

    fun status(handle: Pointer): NodeStatus {
        val b = ByteArray(8192)
        val rc = lib.armax_node_status(handle, b, b.size.toLong())
        if (rc < 0) fail(R.string.err_read_status, rc)
        return parseStatus(cString(b))
    }

    /** Los `limit` movimientos más recientes de la cartera (lo pendiente primero). */
    fun history(handle: Pointer, limit: Int): List<HistoryEntry> {
        val n = limit.coerceIn(1, 500)
        val b = ByteArray(n * 460 + 64)
        val rc = lib.armax_node_history(handle, n, b, b.size.toLong())
        if (rc < 0) fail(R.string.err_read_history, rc)
        val arr = JSONArray(cString(b))
        val out = ArrayList<HistoryEntry>(arr.length())
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            out.add(
                HistoryEntry(
                    kind = o.getString("kind"),
                    amount = o.getString("amount").toLongOrNull() ?: 0L,
                    height = if (o.isNull("height")) null else o.getLong("height"),
                    timestamp = if (o.isNull("timestamp")) null else o.getLong("timestamp"),
                    txid = if (o.isNull("txid")) null else o.getString("txid"),
                    counterparty = if (o.isNull("counterparty")) null else o.getString("counterparty"),
                    confirmations = o.getLong("confirmations"),
                    maturesIn = o.getLong("matures_in"),
                    fee = if (o.isNull("fee")) null else o.getString("fee").toLongOrNull(),
                ),
            )
        }
        return out
    }

    fun send(handle: Pointer, to: String, amountUnits: Long, feeUnits: Long): String {
        val b = ByteArray(256)
        val rc = lib.armax_node_send(handle, to.trim(), amountUnits, feeUnits, b, b.size.toLong())
        if (rc < 0) fail(R.string.err_send, rc)
        return cString(b)
    }

    fun pushSensors(handle: Pointer, tempC: Double, charging: Int, pct: Int, screenOn: Int, memMib: Long) {
        lib.armax_node_push_sensors(handle, tempC, charging, pct, screenOn, memMib)
    }

    fun stop(handle: Pointer) {
        lib.armax_node_stop(handle)
    }

    /** "2.5" → 250000000 unidades; null si el texto no es un monto válido. */
    fun parseAmount(text: String): Long? {
        val out = LongByReference()
        return if (lib.armax_parse_amount(text.trim(), out) >= 0) out.value else null
    }

    private fun parseStatus(json: String): NodeStatus {
        val o = JSONObject(json)
        fun optUnits(k: String): Long? = if (o.isNull(k)) null else o.getString(k).toLongOrNull()
        val m = o.optJSONObject("miner")
        val p = o.optJSONObject("pool")
        return NodeStatus(
            height = o.getLong("height"),
            tip = o.getString("tip"),
            peers = o.getInt("peers"),
            readyPeers = o.getInt("ready_peers"),
            mempool = o.getInt("mempool"),
            syncing = o.getBoolean("syncing"),
            balance = optUnits("balance"),
            spendable = optUnits("spendable"),
            address = if (o.isNull("address")) null else o.getString("address"),
            network = o.getString("network"),
            miner = m?.let {
                MinerStatus(
                    threads = it.getInt("threads"),
                    reason = it.getString("reason"),
                    hashrate = it.getDouble("hashrate"),
                    blocks = it.getLong("blocks"),
                    sharesFound = it.optLong("shares_found", 0),
                    batteryTempC = if (it.isNull("battery_temp_c")) null else it.getDouble("battery_temp_c"),
                )
            },
            pool = p?.let {
                PoolStatus(
                    shares = it.getLong("shares"),
                    orphans = it.getLong("orphans"),
                    myPpm = if (it.isNull("my_ppm")) null else it.getLong("my_ppm"),
                )
            },
        )
    }
}

/** 250000000 → "2.50000000". */
fun formatArm(units: Long?): String {
    if (units == null) return "—"
    val whole = units / UNITS_PER_ARM
    val frac = units % UNITS_PER_ARM
    return "$whole.${frac.toString().padStart(8, '0')}"
}
