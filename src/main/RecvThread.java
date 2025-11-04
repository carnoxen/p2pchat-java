package main;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

import main.State.*;
import main.protocol.Algorithm;
import main.protocol.Method;
import main.protocol.Protocol;

public class RecvThread implements Runnable {
    private SocketContext context;

    public RecvThread(SocketContext context) {
        this.context = context;
    }

    public void parseReceiveData(String recvData) throws Exception {
        var received = Protocol.strToPro(recvData);

        var me = context.getMe();
        var client = context.getClientSocket();
        var mySecretKey = me.secretKey();
        var myIv = me.iv();

        if (Protocol.DEFAULT_PREFIX.equals(received.prefix())) {
            var os = client.getOutputStream();
            var methodString = received.method().toString();
            var otherName = received.header().get("From");

            if (methodString.startsWith("KEYXCHG")) {
                var response = new Protocol();

                var algoString = received.header().get("Algo");
                var otherAlgo = Algorithm.valueOf(algoString);

                switch (received.method()) {
                    case KEYXCHG -> {
                        switch (otherAlgo) {
                            case RSA -> {
                                var receivedPubString = received.body().get(0);

                                var receivedPubKey = context.parsePublicKey(receivedPubString);

                                var you = context.getYou(otherName);
                                if (Objects.nonNull(you) && !receivedPubKey.equals(you.publicKey())) {
                                    response = Protocol.algoProtocol(
                                        Method.KEYXCHGFAIL,
                                        Algorithm.RSA,
                                        me.name(),
                                        otherName,
                                        "Public key is different."
                                    );
                                }

                                context.addYou(new User(
                                    otherName,
                                    receivedPubKey,
                                    null,
                                    null
                                ));
                                response = Protocol.algoProtocol(
                                    Method.KEYXCHGOK,
                                    Algorithm.RSA,
                                    me.name(),
                                    otherName,
                                    me.pubkeyToString(),
                                    you.encryptSecrets(mySecretKey.getEncoded()),
                                    you.encryptSecrets(myIv.getIV())
                                );
                            } 
                            case AES256CBC -> {
                                var receivedSecString = received.body().get(0);
                                var receivedIvString = received.body().get(1);

                                var you = context.getYou(otherName);
                                var receivedPubKey = you.publicKey();
                                var receivedSecKey = context.decryptSecretKey(receivedSecString);
                                var receivedIv = context.decryptIv(receivedIvString);

                                context.addYou(new User(
                                    otherName,
                                    receivedPubKey,
                                    receivedSecKey,
                                    receivedIv
                                ));

                                response = Protocol.algoProtocol(
                                    Method.KEYXCHGOK,
                                    Algorithm.AES256CBC,
                                    me.name(),
                                    otherName
                                );

                                context.setState(new TALKING(otherName));
                            }
                        }
                    }
                    case KEYXCHGOK -> {
                        switch (otherAlgo) {
                            case RSA -> {
                                var receivedPubString = received.body().get(0);
                                var receivedSecString = received.body().get(1);
                                var receivedIvString = received.body().get(2);

                                var receivedPubKey = context.parsePublicKey(receivedPubString);
                                var receivedSecKey = context.decryptSecretKey(receivedSecString);
                                var receivedIv = context.decryptIv(receivedIvString);

                                context.addYou(new User(
                                    otherName,
                                    receivedPubKey,
                                    receivedSecKey,
                                    receivedIv
                                ));

                                var you = context.getYou(otherName);
                                response = Protocol.algoProtocol(
                                    Method.KEYXCHG, 
                                    Algorithm.AES256CBC,
                                    me.name(), 
                                    otherName, 
                                    you.encryptSecrets(mySecretKey.getEncoded()),
                                    you.encryptSecrets(myIv.getIV())
                                );
                            }
                            case AES256CBC -> {
                                context.setState(new TALKING(otherName));
                            }
                            default -> {}
                        }
                    }
                    case KEYXCHGFAIL -> {
                        response = Protocol.algoProtocol(
                            Method.KEYXCHGRST, 
                            Algorithm.RSA, 
                            me.name(), 
                            otherName, 
                            me.pubkeyToString()
                        );
                    }
                    case KEYXCHGRST -> {
                        var receivedPubString = received.body().get(0);
                        var receivedPubKey = context.parsePublicKey(receivedPubString);

                        context.addYou(new User(
                            otherName,
                            receivedPubKey,
                            null,
                            null
                        ));

                        var you = context.getYou(otherName);
                        response = Protocol.algoProtocol(
                            Method.KEYXCHGOK, 
                            Algorithm.RSA, 
                            me.name(), 
                            otherName, 
                            me.pubkeyToString(),
                            you.encryptSecrets(mySecretKey.getEncoded()),
                            you.encryptSecrets(myIv.getIV())
                        );
                    }
                    default -> {}
                }

                os.write(response.toString().getBytes());
                os.flush();
            } else if (
                Method.MSGRECV == received.method() && 
                context.getState() instanceof TALKING s && 
                otherName.equals(s.name())
            ) {
                var message = received.body().get(0);
                var you = context.getYou(otherName);
                var decrypted = you.decryptMessage(message);

                var reader = context.getLineReader();
                reader.printAbove("%s: %s\n".formatted(otherName, decrypted));
                if ("!exit".equals(message)) {
                    context.setState(new WAITING());
                }
            }
        }
    }

    @Override
    public void run() {
        var client = context.getClientSocket();
        while (!client.isClosed()) {
            try {
                var is = client.getInputStream();
                byte[] recvBytes = new byte[2048];
                int recvSize = is.read(recvBytes);

                if (recvSize == 0) {
                    continue;
                }

                String recv = new String(recvBytes, 0, recvSize, StandardCharsets.UTF_8);
                parseReceiveData(recv);
            } catch (Exception e) {
                IO.println("\r\033[K" + e);
                break;
            }
        }
    }
}
