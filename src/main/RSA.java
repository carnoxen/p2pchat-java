package main;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Base64.*;
import javax.crypto.Cipher;

public class RSA {
    private static final int KEYSIZE = 896;
    private static final String ALGORITHM = "RSA";
    private static final Encoder ENCODER = Base64.getEncoder();
    private static final Decoder DECODER = Base64.getDecoder();

    public static KeyPair generateKeyPair() throws Exception {
        var keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(KEYSIZE);
        return keyPairGenerator.genKeyPair();
    }

    public static PublicKey parsePublicKey(String data) throws Exception {
        var keyFactory = KeyFactory.getInstance(ALGORITHM);
        byte[] bytePublicKey = DECODER.decode(data);
        var publicKeySpec = new X509EncodedKeySpec(bytePublicKey);

        return keyFactory.generatePublic(publicKeySpec);
    }

    public static String toEncodedString(PublicKey publicKey) {
        return ENCODER.encodeToString(publicKey.getEncoded());
    }

    public static String encrypt(byte[] plain, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] encryptedData = cipher.doFinal(plain);
        return ENCODER.encodeToString(encryptedData);
    }

    public static byte[] decrypt(String encrypted, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] encryptedData = DECODER.decode(encrypted);
        return cipher.doFinal(encryptedData);
    }
}
