import main.RecvThread;
import main.SendThread;
import main.SocketContext;

void main(String[] args) throws Exception {
    SocketContext sc = new SocketContext("homework.islab.work", 8080);

    Thread sendThread = new Thread(new SendThread(sc));
    Thread recvThread = new Thread(new RecvThread(sc));

    sendThread.start();
    recvThread.start();
}