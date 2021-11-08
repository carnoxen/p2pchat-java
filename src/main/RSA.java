package main;

import java.security.*;
import java.util.Base64;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;

public class RSA {
	private static final int keysize = 896;
	
	public static String[] getKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keysize);
        KeyPair keyPair = keyPairGenerator.genKeyPair();

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        
        String[] arrayS = { 
    		Base64.getEncoder().encodeToString(publicKey.getEncoded()), 
    		Base64.getEncoder().encodeToString(privateKey.getEncoded())
    	};
		return arrayS;
	}
	
	public static String encrypt(String plain, String key) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] bytePublicKey = Base64.getDecoder().decode(key.getBytes());
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bytePublicKey);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] byteEncryptedData = cipher.doFinal(plain.getBytes());
        return Base64.getEncoder().encodeToString(byteEncryptedData);
	}
	
	public static String decrypt(String encrypted, String key) throws Exception {
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] bytePrivateKey = Base64.getDecoder().decode(key.getBytes());
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bytePrivateKey);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] byteEncryptedData = Base64.getDecoder().decode(encrypted.getBytes());
        byte[] byteDecryptedData = cipher.doFinal(byteEncryptedData);
        return new String(byteDecryptedData);
	}
}
