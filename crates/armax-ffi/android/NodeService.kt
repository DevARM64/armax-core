// BOCETO SIN COMPILAR NI PROBAR. Servicio en primer plano que corre el nodo y empuja sensores.
package org.armax.app

import android.app.Service
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager
import android.os.IBinder
import android.os.PowerManager
import com.sun.jna.Pointer
import com.sun.jna.ptr.PointerByReference

class NodeService : Service() {
    private var handle: Pointer? = null
    private var running = false

    override fun onBind(i: Intent?): IBinder? = null

    override fun onStartCommand(i: Intent?, f: Int, id: Int): Int {
        // startForeground(...) con notificación persistente: obligatorio para minar en segundo plano
        val lib = ArmaxLib.INSTANCE
        val vault = KeystoreVault().native()
        val sealed = filesDir.resolve("wallet.sealed").readBytes()
        val cfg = """{"network":"devnet","data_dir":"${filesDir.resolve("chain").absolutePath}","mine":true,"threads":1,"use_governor":true,"connect":"SEMILLA:8333"}"""
        val h = PointerByReference()
        check(lib.armax_node_start(cfg, vault, sealed, sealed.size.toLong(), h) == 0)
        handle = h.value
        running = true
        Thread {
            val pm = getSystemService(POWER_SERVICE) as PowerManager
            while (running) {
                val b = registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))!!
                val temp = b.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, Int.MIN_VALUE) / 10.0 // décimas de °C
                val status = b.getIntExtra(BatteryManager.EXTRA_STATUS, -1)
                val charging = if (status == BatteryManager.BATTERY_STATUS_CHARGING || status == BatteryManager.BATTERY_STATUS_FULL) 1 else 0
                val pct = b.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
                val screen = if (pm.isInteractive) 1 else 0
                lib.armax_node_push_sensors(handle!!, if (temp < -100) Double.NaN else temp, charging, pct, screen, -1)
                Thread.sleep(5_000)
            }
        }.start()
        return START_STICKY
    }

    override fun onDestroy() {
        running = false
        handle?.let { ArmaxLib.INSTANCE.armax_node_stop(it) }
        super.onDestroy()
    }
}
