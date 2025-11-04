package main;

import java.security.*;

public class RSA {
    private static final int KEYSIZE = 896;
    private static final String ALGORITHM = "RSA";

    public static KeyPair generateKeyPair() throws Exception {
        var keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(KEYSIZE);
        return keyPairGenerator.genKeyPair();
    }
}
