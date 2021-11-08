package main;

import java.io.IOException;
import java.net.Socket;

public class SocketContext {
    private final Socket clientSocket;
    private User me;
    private State state;
    
    public SocketContext(String host, int port) throws IOException {
    	clientSocket = new Socket(host, port);
        me = new User();
        state = State.from;
    }
    
    public synchronized Socket getClientSocket() {
    	return clientSocket;
    }
    
    public synchronized User getMe() {
    	return me;
    }
    
    public synchronized State getState() {
    	return state;
    }
    
    public synchronized void setMe(User user) {
    	me = user;
    }
    
    public synchronized void setState(State state) {
    	this.state = state;
    }
}
