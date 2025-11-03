package main;

import java.net.Socket;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Map;

public class SocketContext {
    private final Socket clientSocket;
    private final PrivateKey privateKey;
    private final User me;
    private State state = new State.START();
    private Map<String, User> youMap = new HashMap<>();

    public SocketContext(String host, int port) throws Exception {
        String name = IO.readln("input your name:");

        clientSocket = new Socket(host, port);
        var keypair = RSA.generateKeyPair();
        this.privateKey = keypair.getPrivate();
        this.me = new User(
            name,
            keypair.getPublic(),
            AES.generateKey(),
            AES.generateIvParameterSpec()
        );
    }

    public synchronized Socket getClientSocket() {
        return clientSocket;
    }

    public synchronized User getMe() {
        return me;
    }

    public synchronized Map<String, User> getYouMap() {
        return youMap;
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
}
