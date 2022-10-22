package org.example

import org.example.AESCipher.decrypt
import org.example.AESCipher.encrypt
import org.example.AESCipher.generateAESKey
import java.util.*

object MessageSecureProcessor {
    private const val ENCODE_START = "@ENCODE@"
    private const val SPLITER = "@_@"
    private const val ENCRYPTED_FORM = "$ENCODE_START%s$SPLITER%s "

    fun encrypt(message: String, publicKey: ByteArray?): String {
        val aesKeyBytes = generateAESKey()
        val base64EncryptedMessage =
            Base64.getMimeEncoder().encodeToString(encrypt(message.toByteArray(), aesKeyBytes!!))
        val base64EncryptedKey = Base64.getMimeEncoder().encodeToString(RSACipher.encrypt(aesKeyBytes, publicKey))
        return String.format(ENCRYPTED_FORM, base64EncryptedKey, base64EncryptedMessage)
    }

    fun decrypt(message: String, privateKey: ByteArray?): String? {
        val parts = message.split(SPLITER.toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val base64EncryptedKey = parts[0].replace(ENCODE_START, "")
        val base64EncryptedMessage = parts[1]
        try {
            val aesKey = RSACipher.decrypt(Base64.getMimeDecoder().decode(base64EncryptedKey), privateKey)
            return String(decrypt(Base64.getMimeDecoder().decode(base64EncryptedMessage), aesKey!!)!!)
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }
}