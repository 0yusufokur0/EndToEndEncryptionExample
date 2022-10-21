package org.example;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class AESCipher {

    public static byte[] generateAESKey() {
        try {
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(256); // 192 and 256 bits may not be available
            SecretKey skey = kgen.generateKey();
            return skey.getEncoded();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] encrypt(byte[] input, byte[] key) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            SecretKey secretKey = new SecretKeySpec(key, 0, key.length, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher.doFinal(input);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] decrypt(byte[] input, byte[] key) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            SecretKey originalKey = new SecretKeySpec(key, 0, key.length, "AES");
            cipher.init(Cipher.DECRYPT_MODE, originalKey);
            return cipher.doFinal(input);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }
}
