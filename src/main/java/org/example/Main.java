package org.example;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Main {

    static class User {

        public PublicKey publicKey;
        public PrivateKey privateKey;

        void init(){
            KeyPair keyPair = RSACipher.generateKeyPair();

            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
        }
    }

    public static void main(String[] args) {

        User aUser = new User();
        User bUser = new User();

        aUser.init();
        bUser.init();

        // A User
        String aUserMessage = "hello world";
        String aUserEncryptedMessage = MessageSecureProcessor.encrypt(aUserMessage , bUser.publicKey.getEncoded());
        System.out.println("aUserEncryptedMessage = " + aUserEncryptedMessage);

        // B User
        String bUserDecryptedMessage = MessageSecureProcessor.decrypt(aUserEncryptedMessage , bUser.privateKey.getEncoded());
        System.out.println("bUserDecryptedMessage = " + bUserDecryptedMessage);




/*
        KeyPair keyPair = RSACipher.generateKeyPair();

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        System.out.println("private key = "+ privateKey);
        System.out.println("public key = " + publicKey);

        System.out.println("private key = "+ privateKey.getEncoded());
        System.out.println("public key = " + publicKey.getEncoded());


        String enc = MessageSecureProcessor.encrypt("a" , publicKey.getEncoded());
        System.out.println(enc);

        String dec = MessageSecureProcessor.decrypt(enc,privateKey.getEncoded());
        System.out.println(dec);
*/

    }
}