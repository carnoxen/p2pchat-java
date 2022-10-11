package main;

import java.security.*;
import java.util.Base64;

import javax.crypto.*;
import javax.crypto.spec.*;

public class AES {
    private static final int keysize = 256;
    private static final int vectorsize = keysize / 2;

    public static String[] getKeySet() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keysize); // for example
        SecretKey secretKey = keyGen.generateKey();

        String keyString = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        byte[] iv = new byte[vectorsize / Byte.SIZE];
        new SecureRandom().nextBytes(iv);
        String ivString = Base64.getEncoder().encodeToString(iv);

        String[] keyset = { keyString, ivString };
        return keyset;
    }

    public static String encrypt(String plain, String key, String ivString) throws Exception {
        byte[] byteSecretKey = Base64.getDecoder().decode(key.getBytes());
        SecretKeySpec secretKeySpec = new SecretKeySpec(byteSecretKey, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = Base64.getDecoder().decode(ivString);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));

        byte[] byteEncryptedData = cipher.doFinal(plain.getBytes());
        return Base64.getEncoder().encodeToString(byteEncryptedData);
    }

    public static String decrypt(String encrypted, String key, String ivString) throws Exception {
        byte[] byteSecretKey = Base64.getDecoder().decode(key.getBytes());
        SecretKeySpec secretKeySpec = new SecretKeySpec(byteSecretKey, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = Base64.getDecoder().decode(ivString);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));

        byte[] byteEncryptedData = Base64.getDecoder().decode(encrypted.getBytes());
        byte[] byteDecryptedData = cipher.doFinal(byteEncryptedData);
        return new String(byteDecryptedData);
    }
}
