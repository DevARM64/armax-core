// BOCETO SIN COMPILAR NI PROBAR. Bóveda AES-GCM con clave no exportable del Android Keystore.
package org.armax.app

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.sun.jna.Pointer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class KeystoreVault(private val alias: String = "armax_wallet_key") {
    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        val g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        g.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                // .setUserAuthenticationRequired(true)  // activar para exigir huella/PIN
                .build()
        )
        return g.generateKey()
    }

    private fun put(data: ByteArray, out: Pointer, cap: Long, outLen: Pointer): Int {
        if (data.size > cap) return 7
        out.write(0, data, 0, data.size)
        outLen.setLong(0, data.size.toLong()) // size_t de 64 bits en arm64
        return 0
    }

    // IMPORTANTE: callbacks guardados en campos para que el GC no los recoja mientras Rust los usa.
    val sealFn = object : VaultFn {
        override fun invoke(ctx: Pointer?, input: Pointer?, inputLen: Long, out: Pointer, outCap: Long, outLen: Pointer): Int = try {
            val plain = input?.getByteArray(0, inputLen.toInt()) ?: ByteArray(0)
            val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
            put(c.iv + c.doFinal(plain), out, outCap, outLen) // IV(12) | cifrado+etiqueta
        } catch (e: Exception) { 1 }
    }
    val openFn = object : VaultFn {
        override fun invoke(ctx: Pointer?, input: Pointer?, inputLen: Long, out: Pointer, outCap: Long, outLen: Pointer): Int = try {
            val all = input!!.getByteArray(0, inputLen.toInt())
            val c = Cipher.getInstance("AES/GCM/NoPadding")
                .apply { init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, all, 0, 12)) }
            put(c.doFinal(all, 12, all.size - 12), out, outCap, outLen)
        } catch (e: Exception) { 2 }
    }

    fun native(): ArmaxVault = ArmaxVault().also { it.seal = sealFn; it.open = openFn; it.write() }
}
