// Servicio en primer plano: arranca el nodo (y el minero), le empuja los sensores del teléfono
// cada pocos segundos y publica el estado en NodeState. Android exige la notificación fija para
// que un servicio pueda seguir trabajando con la pantalla apagada.
package org.armax.app

import android.app.ActivityManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.os.BatteryManager
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import org.json.JSONObject
import java.io.File

class NodeService : Service() {

    @Volatile private var loopRunning = false
    private var worker: Thread? = null
    private var wakeLock: PowerManager.WakeLock? = null

    companion object {
        const val ACTION_STOP = "org.armax.app.STOP"
        private const val CHANNEL = "armax_node"
        private const val NOTIF_ID = 1

        fun sealedFile(ctx: Context) = File(ctx.filesDir, "wallet.sealed")
        /** Cada red guarda su cadena aparte (el archivo de bloques lleva el génesis de su red). `fast` conserva la carpeta original. */
        fun dataDir(ctx: Context, network: String) = File(ctx.filesDir, if (network == "fast") "chain" else "chain-$network")

        fun start(ctx: Context) {
            ContextCompat.startForegroundService(ctx, Intent(ctx, NodeService::class.java))
        }

        fun stop(ctx: Context) {
            ctx.stopService(Intent(ctx, NodeService::class.java))
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return START_NOT_STICKY
        }
        createChannel()
        val n = notification(getString(R.string.notif_starting))
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, n)
        }
        if (worker?.isAlive == true) return START_STICKY // ya en marcha
        loopRunning = true
        worker = Thread({ nodeLoop() }, "armax-node").also { it.start() }
        return START_STICKY
    }

    private fun nodeLoop() {
        val ctx = applicationContext
        val handle = try {
            val sealed = sealedFile(ctx).readBytes()
            val settings = SettingsStore(ctx).load()
            dataDir(ctx, settings.network).mkdirs()
            Armax.startNode(configJson(settings), KeystoreVault().native(), sealed)
        } catch (e: Throwable) {
            NodeState.setError(e.message ?: e.toString())
            stopSelf()
            return
        }
        NodeState.nodeStarted(handle)

        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        // sin esto el procesador se duerme con la pantalla apagada y el nodo pierde a sus pares
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "armax:node").also { it.acquire() }

        var tick = 0
        while (loopRunning) {
            try {
                if (tick % 5 == 0) pushSensors(pm)
                NodeState.withHandle { h -> NodeState.publish(Armax.status(h)) }
                if (tick % 15 == 0) updateNotification()
            } catch (e: Throwable) {
                NodeState.setError(e.message ?: e.toString())
            }
            tick++
            try {
                Thread.sleep(1_000)
            } catch (e: InterruptedException) {
                break
            }
        }
    }

    private fun configJson(s: Settings): String {
        val c = JSONObject()
        c.put("network", s.network)
        c.put("data_dir", dataDir(applicationContext, s.network).absolutePath)
        c.put("mine", s.mine)
        c.put("pool", s.pool)
        c.put("threads", s.threads)
        c.put("any_power", s.anyPower)
        c.put("min_battery", s.minBattery)
        c.put("pause_when_screen_on", !s.mineWithScreenOn)
        c.put("use_governor", true)
        if (s.connect.isNotBlank()) c.put("connect", s.connect.trim())
        if (s.pin.isNotBlank()) c.put("pin", s.pin.trim())
        return c.toString()
    }

    /** Lecturas del teléfono para el gobernador térmico (si faltan, el minero no arranca: falla seguro). */
    private fun pushSensors(pm: PowerManager) {
        val b = registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED)) ?: return
        val tempTenths = b.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, Int.MIN_VALUE)
        val temp = if (tempTenths == Int.MIN_VALUE) Double.NaN else tempTenths / 10.0
        val status = b.getIntExtra(BatteryManager.EXTRA_STATUS, -1)
        val charging = if (status == BatteryManager.BATTERY_STATUS_CHARGING || status == BatteryManager.BATTERY_STATUS_FULL) 1 else 0
        val level = b.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
        val scale = b.getIntExtra(BatteryManager.EXTRA_SCALE, 100)
        val pct = if (level >= 0 && scale > 0) level * 100 / scale else -1
        val screen = if (pm.isInteractive) 1 else 0
        val mi = ActivityManager.MemoryInfo()
        (getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager).getMemoryInfo(mi)
        val memMib = mi.availMem / (1024 * 1024)
        NodeState.withHandle { h -> Armax.pushSensors(h, temp, charging, pct, screen, memMib) }
    }

    private fun createChannel() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(CHANNEL) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL, getString(R.string.notif_channel), NotificationManager.IMPORTANCE_LOW)
            )
        }
    }

    private fun notification(text: String): Notification {
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stop = PendingIntent.getService(
            this, 1, Intent(this, NodeService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_armax)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(open)
            .addAction(0, getString(R.string.notif_stop), stop)
            .build()
    }

    private fun updateNotification() {
        val s = NodeState.status.value ?: return
        val m = s.miner
        val text = if (m != null) {
            getString(R.string.notif_status_mining, s.height, s.readyPeers, "%.1f".format(m.hashrate), reasonLabel(this, m.reason))
        } else {
            getString(R.string.notif_status, s.height, s.readyPeers)
        }
        (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).notify(NOTIF_ID, notification(text))
    }

    override fun onDestroy() {
        loopRunning = false
        worker?.interrupt()
        try {
            worker?.join(3_000)
        } catch (e: InterruptedException) {
            // se sigue con el cierre
        }
        NodeState.stopNode()
        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null
        super.onDestroy()
    }
}

/** Motivo del gobernador térmico, en el idioma del teléfono. */
fun reasonLabel(ctx: Context, reason: String): String {
    val id = when (reason) {
        "Running" -> R.string.reason_Running
        "Ramping" -> R.string.reason_Ramping
        "LimitedByTemperature" -> R.string.reason_LimitedByTemperature
        "LimitedByMemory" -> R.string.reason_LimitedByMemory
        "NoTemperatureSensor" -> R.string.reason_NoTemperatureSensor
        "NoChargingInfo" -> R.string.reason_NoChargingInfo
        "NotCharging" -> R.string.reason_NotCharging
        "LowBattery" -> R.string.reason_LowBattery
        "ScreenOn" -> R.string.reason_ScreenOn
        "Overheated" -> R.string.reason_Overheated
        "Cooling" -> R.string.reason_Cooling
        "LowMemory" -> R.string.reason_LowMemory
        "sin gobernador" -> R.string.reason_NoGovernor
        else -> return reason
    }
    return ctx.getString(id)
}

/** 0 = marcha normal, 1 = limitada o a medias, 2 = detenida. Para colorear el estado del minero. */
fun reasonSeverity(reason: String): Int = when (reason) {
    "Running", "Ramping", "sin gobernador" -> 0
    "LimitedByTemperature", "LimitedByMemory", "NotCharging", "LowBattery", "ScreenOn", "Cooling", "LowMemory" -> 1
    else -> 2
}
