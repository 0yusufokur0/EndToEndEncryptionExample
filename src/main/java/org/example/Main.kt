package org.example

import java.security.PrivateKey
import java.security.PublicKey

object Main {
    @JvmStatic
    fun main(args: Array<String>) {
        val aUser = User()
        val bUser = User()
        aUser.init()
        bUser.init()

        // A User
        val aUserMessage = "hello world"
        val aUserEncryptedMessage = MessageSecureProcessor.encrypt(aUserMessage, bUser.publicKey!!.encoded)
        println("aUserEncryptedMessage = $aUserEncryptedMessage")

        // B User
        val bUserDecryptedMessage = MessageSecureProcessor.decrypt(aUserEncryptedMessage, bUser.privateKey!!.encoded)
        println("bUserDecryptedMessage = $bUserDecryptedMessage")
        val keyPair = RSACipher.generateKeyPair()
        val publicKey = keyPair?.public
        val privateKey = keyPair?.private
        println("private key = $privateKey")
        println("public key = $publicKey")
        println("private key = " + privateKey?.encoded)
        println("public key = " + publicKey?.encoded)
        val enc = MessageSecureProcessor.encrypt("a", publicKey?.encoded)
        println(enc)
        val dec = MessageSecureProcessor.decrypt(enc, privateKey?.encoded)
        println(dec)
    }

    internal class User {
        var publicKey: PublicKey? = null
        var privateKey: PrivateKey? = null
        fun init() {
            val keyPair = RSACipher.generateKeyPair()
            publicKey = keyPair?.public
            privateKey = keyPair?.private
        }
    }
}