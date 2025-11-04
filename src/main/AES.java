package main;

import java.security.*;

import javax.crypto.*;
import javax.crypto.spec.*;

public class AES {
    private static final int KEYSIZE = 256;
    private static final int VECTORSIZE = KEYSIZE / 2;
    private static final String ALGORITHM = "AES";

    public static SecretKey generateKey() throws Exception {
        var keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(KEYSIZE);
        return keyGen.generateKey();
    }

    public static IvParameterSpec generateIv() throws Exception {
        byte[] iv = new byte[VECTORSIZE / Byte.SIZE];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
}
