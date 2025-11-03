package main;

import java.nio.charset.StandardCharsets;

import main.State.*;
import main.protocol.Algorithm;
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

        return Protocol.algoProtocol(
            Method.KEYXCHG, 
            Algorithm.RSA, 
            me.name(), 
            otherName, 
            RSA.toEncodedString(me.publicKey())
        );
    }

    private Protocol sendMessage(String otherName, String message) throws Exception {
        var me = context.getMe();

        return Protocol.msgProtocol(
            me.name(), 
            otherName, 
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
                    case START _ -> {
                        context.setState(new WAITING());
                    }
                    case WAITING _ -> {
                        String command = IO.readln("Command: ").trim();
                        if (command.startsWith("disconnect")) {
                            sending = sendDisconnect();
                        }
                        else if (
                            command.startsWith("keyexc") &&
                            command.split(" ").length > 1
                        ) {
                            String otherName = command.split(" ")[1];
                            sending = sendKeyexc(otherName);
                        }
                    }
                    case TALKING t -> {
                        String message = IO.readln("> ").trim();
                        sending = sendMessage(t.name(), message);
                        if ("!exit".equals(message)) {
                            context.setState(new WAITING());
                        }
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
