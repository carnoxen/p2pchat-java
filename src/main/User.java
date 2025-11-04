package main;

import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public record User(
    String name,
    PublicKey publicKey,
    SecretKey secretKey,
    IvParameterSpec iv
) {
    private static final String RSA_ALGORITHM = "RSA";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final Base64.Encoder ENCODER = Base64.getEncoder();
    private static final Base64.Decoder DECODER = Base64.getDecoder();

    public String pubkeyToString() {
        return ENCODER.encodeToString(this.publicKey.getEncoded());
    }

    public String encryptSecrets(byte[] plain) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);

        byte[] encryptedData = cipher.doFinal(plain);
        return ENCODER.encodeToString(encryptedData);
    }

    public String encryptMessage(String plain) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

        byte[] encryptedData = cipher.doFinal(plain.getBytes());
        return ENCODER.encodeToString(encryptedData);
    }

    public String decryptMessage(String encoded) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

        byte[] encryptedData = DECODER.decode(encoded);
        return new String(cipher.doFinal(encryptedData));
    }
}
