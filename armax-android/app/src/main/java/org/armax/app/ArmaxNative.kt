// Enlace JNA con libarmax_ffi.so (ver crates/armax-ffi/include/armax.h).
// En arm64 `size_t`, `long` y los punteros son de 64 bits: se declaran como Long.
package org.armax.app

import com.sun.jna.Callback
import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.Structure
import com.sun.jna.ptr.LongByReference
import com.sun.jna.ptr.PointerByReference

/** Callback de la bóveda: lee `input`, escribe en `out` y deja los bytes escritos en `outLen`. 0 = ok. */
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

    fun armax_wallet_create(
        vault: ArmaxVault, mnemonicOut: ByteArray, mnemonicCap: Long,
        sealedOut: ByteArray, sealedCap: Long, sealedLen: LongByReference,
    ): Int

    fun armax_wallet_restore(
        vault: ArmaxVault, mnemonic: String,
        sealedOut: ByteArray, sealedCap: Long, sealedLen: LongByReference,
    ): Int

    fun armax_wallet_address(vault: ArmaxVault, sealed: ByteArray, sealedLen: Long, out: ByteArray, cap: Long): Int

    fun armax_node_start(
        configJson: String, vault: ArmaxVault?, sealed: ByteArray?, sealedLen: Long,
        outHandle: PointerByReference,
    ): Int

    fun armax_node_status(handle: Pointer, out: ByteArray, cap: Long): Int
    fun armax_node_history(handle: Pointer, limit: Int, out: ByteArray, cap: Long): Int
    fun armax_node_send(handle: Pointer, to: String, amountUnits: Long, feeUnits: Long, out: ByteArray, cap: Long): Int
    fun armax_node_push_sensors(handle: Pointer, tempC: Double, charging: Int, pct: Int, screenOn: Int, memMib: Long): Int
    fun armax_node_stop(handle: Pointer): Int
    fun armax_parse_amount(text: String, outUnits: LongByReference): Int

    companion object {
        val INSTANCE: ArmaxLib by lazy { Native.load("armax_ffi", ArmaxLib::class.java) }
    }
}
