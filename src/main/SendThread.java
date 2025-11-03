package main;

import java.nio.charset.StandardCharsets;

import main.protocol.Method;
import main.protocol.Protocol;

public class SendThread implements Runnable {
    private SocketContext context;

    public SendThread(SocketContext context) {
        this.context = context;
    }

    private Protocol sendConnect() {
        var me = context.getMe();
        return Protocol.connProtocol(
            Method.CONNECT,
            me.name()
        );
    }

    private Protocol sendDisconnect() {
        var me = context.getMe();
        return Protocol.connProtocol(
            Method.DISCONNECT,
            me.name()
        );
    }

    private Protocol sendKeyexc(String otherName) {
        var me = context.getMe();
        var pubkey = me.publicKey();

        return Protocol.algoProtocol(
            Method.KEYXCHG, 
            "RSA", 
            me.name(), 
            otherName, 
            RSA.toEncodedString(pubkey)
        );
    }

    private Protocol sendMessage(String otherName, String message) throws Exception {
        var me = context.getMe();
        var you = context.getYouMap().get(otherName);

        return Protocol.msgProtocol(
            me.name(), 
            you.name(), 
            AES.encrypt(message, me)
        );
    }

    @Override
    public void run() {
        var client = context.getClientSocket();

        while (!client.isClosed()) {
            try {
                var os = client.getOutputStream();
                Protocol sending = sendConnect();

                switch (context.getState()) {
                    case State.START _ -> {
                        context.setState(new State.WAITING());
                    }
                    case State.WAITING _ -> {
                        String otherName = IO.readln("input friend's name:");
                        sending = sendKeyexc(otherName);
                    }
                    case State.TALKING t -> {
                        String message = IO.readln("> ");
                        if ("!exit".equals(message)) {
                            sending = sendDisconnect();
                            context.setState(new State.WAITING());
                        }
                        sending = sendMessage(t.name(), message);
                    }
                    default -> {
                        IO.println("Some Error Encountered");
                    }
                }

                byte[] payload = sending.toString().getBytes(StandardCharsets.UTF_8);
                os.write(payload, 0, payload.length);
                os.flush();
            } catch (Exception e) {
                IO.println(e);
                break;
            }
        }
    }

}
