package main;

import java.security.*;
import java.util.Base64;
import java.util.Base64.*;

import javax.crypto.*;
import javax.crypto.spec.*;

public class AES {
    private static final int KEYSIZE = 256;
    private static final int VECTORSIZE = KEYSIZE / 2;
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final Encoder ENCODER = Base64.getEncoder();
    private static final Decoder DECODER = Base64.getDecoder();

    public static SecretKey generateKey() throws Exception {
        var keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(KEYSIZE);
        return keyGen.generateKey();
    }

    public static IvParameterSpec generateIvParameterSpec() throws Exception {
        byte[] iv = new byte[VECTORSIZE / Byte.SIZE];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static SecretKey parseSecretKey(byte[] data) throws Exception {
        return new SecretKeySpec(data, ALGORITHM);
    }

    public static IvParameterSpec parseIv(byte[] data) throws Exception {
        return new IvParameterSpec(data);
    }

    public static String encrypt(String plain, User user) throws Exception {
        var secretKey = user.secretKey();
        var ivParameterSpec = user.ivParameterSpec();
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

        byte[] encryptedData = cipher.doFinal(plain.getBytes());
        return ENCODER.encodeToString(encryptedData);
    }

    public static String decrypt(String encrypted, User user) throws Exception {
        var secretKey = user.secretKey();
        var ivParameterSpec = user.ivParameterSpec();
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

        byte[] encryptedData = DECODER.decode(encrypted);
        return new String(cipher.doFinal(encryptedData));
    }
}
