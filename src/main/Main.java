package main;

import java.io.IOException;

public class Main {

    public static void main(String[] args) throws IOException, InterruptedException {
        // TODO Auto-generated method stub
        SocketContext sc = new SocketContext("homework.islab.work", 8080);

        Thread sendThread = new Thread(new SendThread(sc));
        Thread recvThread = new Thread(new RecvThread(sc));

        sendThread.start();
        recvThread.start();
    }

}
