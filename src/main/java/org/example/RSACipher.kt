package org.example

import java.security.*
import java.security.interfaces.RSAPublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException

object RSACipher {
    fun generateKeyPair(): KeyPair? {
        try {
            val keyGen = KeyPairGenerator.getInstance("RSA")
            keyGen.initialize(2048)
            return keyGen.generateKeyPair()
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
        }
        return null
    }

    fun encrypt(keyBytes: ByteArray?, pubBytes: ByteArray?): ByteArray? {
        val keyFactory: KeyFactory
        try {
            keyFactory = KeyFactory.getInstance("RSA")
            val KeySpec = X509EncodedKeySpec(pubBytes)
            val pubKey = keyFactory.generatePublic(KeySpec) as RSAPublicKey
            val cipher = Cipher.getInstance("RSA")
            cipher.init(Cipher.ENCRYPT_MODE, pubKey)
            return cipher.doFinal(keyBytes)
        }
        catch (e: NoSuchAlgorithmException) { e.printStackTrace() }
        catch (e: InvalidKeyException) { e.printStackTrace() }
        catch (e: NoSuchPaddingException) { e.printStackTrace() }
        catch (e: BadPaddingException) { e.printStackTrace() }
        catch (e: InvalidKeySpecException) { e.printStackTrace() }
        catch (e: IllegalBlockSizeException) { e.printStackTrace() }
        return null
    }

    fun decrypt(keyBytes: ByteArray?, priBytes: ByteArray?): ByteArray? {
        val keyFactory: KeyFactory
        try {
            keyFactory = KeyFactory.getInstance("RSA")
            val privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(priBytes))
            val cipher = Cipher.getInstance("RSA")
            cipher.init(Cipher.DECRYPT_MODE, privateKey)
            return cipher.doFinal(keyBytes)
        }
        catch (e: NoSuchAlgorithmException) { e.printStackTrace() }
        catch (e: InvalidKeyException) { e.printStackTrace() }
        catch (e: NoSuchPaddingException) { e.printStackTrace() }
        catch (e: BadPaddingException) { e.printStackTrace() }
        catch (e: InvalidKeySpecException) { e.printStackTrace() }
        catch (e: IllegalBlockSizeException) { e.printStackTrace() }
        return null
    }
}