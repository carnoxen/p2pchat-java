package main;

import java.net.Socket;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SocketContext {
    private static final String AES_ALGORITHM = "AES";
    private static final String RSA_ALGORITHM = "RSA";
    private static final Base64.Decoder DECODER = Base64.getDecoder();

    private final Socket clientSocket;
    private final PrivateKey privateKey;
    private final User me;
    private State state = new State.START();
    private Map<String, User> youMap = new HashMap<>();

    public SocketContext(String host, int port) throws Exception {
        String name = IO.readln("input your name:");
        var keypair = RSA.generateKeyPair();

        this.clientSocket = new Socket(host, port);
        this.privateKey = keypair.getPrivate();
        this.me = new User(
            name,
            keypair.getPublic(),
            AES.generateKey(),
            AES.generateIv()
        );
    }

    public synchronized Socket getClientSocket() {
        return clientSocket;
    }

    public synchronized User getMe() {
        return me;
    }

    public synchronized User getYou(String name) {
        return youMap.get(name);
    }

    public synchronized PrivateKey getPrivateKey() {
        return privateKey;
    }

    public synchronized State getState() {
        return state;
    }

    public synchronized void addYou(User user) {
        this.youMap.put(user.name(), user);
    }

    public synchronized void deleteYou(User user) {
        this.youMap.remove(user.name());
    }

    public synchronized void setState(State state) {
        this.state = state;
    }

    public PublicKey parsePublicKey(String encoded) throws Exception {
        var keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        byte[] data = DECODER.decode(encoded);
        var keySpec = new X509EncodedKeySpec(data);

        return keyFactory.generatePublic(keySpec);
    }

    private byte[] decryptSecrets(String encoded) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, this.privateKey);

        byte[] encryptedData = DECODER.decode(encoded);
        return cipher.doFinal(encryptedData);
    }

    public SecretKey decryptSecretKey(String encoded) throws Exception {
        byte[] data = this.decryptSecrets(encoded);
        return new SecretKeySpec(data, AES_ALGORITHM);
    }

    public IvParameterSpec decryptIv(String encoded) throws Exception {
        byte[] data = this.decryptSecrets(encoded);
        return new IvParameterSpec(data);
    }
}
