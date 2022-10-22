package org.example

import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import javax.crypto.*
import javax.crypto.spec.SecretKeySpec

object AESCipher {
    @JvmStatic
    fun generateAESKey(): ByteArray? {
        return try {
            val kgen = KeyGenerator.getInstance("AES")
            kgen.init(256) // 192 and 256 bits may not be available
            val skey = kgen.generateKey()
            skey.encoded
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
            null
        }
    }

    @JvmStatic
    fun encrypt(input: ByteArray?, key: ByteArray): ByteArray? {
        try {
            val cipher = Cipher.getInstance("AES")
            val secretKey: SecretKey = SecretKeySpec(key, 0, key.size, "AES")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            return cipher.doFinal(input)
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
        } catch (e: NoSuchPaddingException) {
            e.printStackTrace()
        } catch (e: InvalidKeyException) {
            e.printStackTrace()
        } catch (e: BadPaddingException) {
            e.printStackTrace()
        } catch (e: IllegalBlockSizeException) {
            e.printStackTrace()
        }
        return null
    }

    @JvmStatic
    fun decrypt(input: ByteArray?, key: ByteArray): ByteArray? {
        try {
            val cipher = Cipher.getInstance("AES")
            val originalKey: SecretKey = SecretKeySpec(key, 0, key.size, "AES")
            cipher.init(Cipher.DECRYPT_MODE, originalKey)
            return cipher.doFinal(input)
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
        } catch (e: NoSuchPaddingException) {
            e.printStackTrace()
        } catch (e: InvalidKeyException) {
            e.printStackTrace()
        } catch (e: BadPaddingException) {
            e.printStackTrace()
        } catch (e: IllegalBlockSizeException) {
            e.printStackTrace()
        }
        return null
    }
}