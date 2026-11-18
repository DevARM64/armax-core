// BOCETO SIN COMPILAR NI PROBAR: no hay Android SDK en el entorno de desarrollo del núcleo.
// Requiere JNA (net.java.dev.jna:jna:5.x@aar) y libarmax_ffi.so en app/src/main/jniLibs/arm64-v8a/.
package org.armax.app

import com.sun.jna.Callback
import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.Structure
import com.sun.jna.ptr.IntByReference
import com.sun.jna.ptr.PointerByReference

interface VaultFn : Callback {
    fun invoke(ctx: Pointer?, input: Pointer?, inputLen: Long, out: Pointer, outCap: Long, outLen: Pointer): Int
}

@Structure.FieldOrder("ctx", "seal", "open")
open class ArmaxVault : Structure() {
    @JvmField var ctx: Pointer? = null
    @JvmField var seal: VaultFn? = null
    @JvmField var open: VaultFn? = null
}

interface ArmaxLib : Library {
    fun armax_version(out: ByteArray, cap: Long): Int
    fun armax_last_error(out: ByteArray, cap: Long): Int
    fun armax_wallet_create(v: ArmaxVault, mn: ByteArray, mnCap: Long, sealed: ByteArray, sealedCap: Long, sealedLen: com.sun.jna.ptr.LongByReference): Int
    fun armax_wallet_restore(v: ArmaxVault, mnemonic: String, sealed: ByteArray, sealedCap: Long, sealedLen: com.sun.jna.ptr.LongByReference): Int
    fun armax_wallet_address(v: ArmaxVault, sealed: ByteArray, sealedLen: Long, out: ByteArray, cap: Long): Int
    fun armax_node_start(configJson: String, v: ArmaxVault?, sealed: ByteArray?, sealedLen: Long, outHandle: PointerByReference): Int
    fun armax_node_status(h: Pointer, out: ByteArray, cap: Long): Int
    fun armax_node_send(h: Pointer, to: String, amount: Long, fee: Long, out: ByteArray, cap: Long): Int
    fun armax_node_push_sensors(h: Pointer, tempC: Double, charging: Int, pct: Int, screenOn: Int, memMib: Long): Int
    fun armax_node_stop(h: Pointer): Int

    companion object {
        val INSTANCE: ArmaxLib by lazy { Native.load("armax_ffi", ArmaxLib::class.java) }
    }
}
