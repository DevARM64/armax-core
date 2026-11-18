// Bóveda: AES-GCM con una clave no exportable del Android Keystore. La cartera nunca se guarda en
// claro: lo que va a disco es el "sellado" (IV | cifrado | etiqueta) y solo ESTE teléfono lo abre.
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
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                // .setUserAuthenticationRequired(true)  // activar para exigir huella/PIN al abrir
                .build()
        )
        return gen.generateKey()
    }

    private fun put(data: ByteArray, out: Pointer, cap: Long, outLen: Pointer): Int {
        if (data.size.toLong() > cap) return 7
        out.write(0, data, 0, data.size)
        outLen.setLong(0, data.size.toLong()) // size_t de 64 bits en arm64
        return 0
    }

    // Se guardan en campos: si el recolector de basura los liberara mientras Rust los usa, se caería.
    private val sealFn = object : VaultFn {
        override fun invoke(ctx: Pointer?, input: Pointer?, inputLen: Long, out: Pointer, outCap: Long, outLen: Pointer): Int =
            try {
                val plain = input?.getByteArray(0, inputLen.toInt()) ?: ByteArray(0)
                val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
                val sealed = c.iv + c.doFinal(plain) // IV (12) | cifrado + etiqueta
                java.util.Arrays.fill(plain, 0)
                put(sealed, out, outCap, outLen)
            } catch (e: Exception) {
                1
            }
    }

    private val openFn = object : VaultFn {
        override fun invoke(ctx: Pointer?, input: Pointer?, inputLen: Long, out: Pointer, outCap: Long, outLen: Pointer): Int =
            try {
                val all = input!!.getByteArray(0, inputLen.toInt())
                val c = Cipher.getInstance("AES/GCM/NoPadding")
                    .apply { init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, all, 0, 12)) }
                val plain = c.doFinal(all, 12, all.size - 12)
                val rc = put(plain, out, outCap, outLen)
                java.util.Arrays.fill(plain, 0)
                rc
            } catch (e: Exception) {
                2
            }
    }

    private val vault = ArmaxVault().also {
        it.seal = sealFn
        it.open = openFn
        it.write()
    }

    fun native(): ArmaxVault = vault
}
