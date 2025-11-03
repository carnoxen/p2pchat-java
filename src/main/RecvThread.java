package main;

import java.nio.charset.StandardCharsets;

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
        var youMap = context.getYouMap();
        var client = context.getClientSocket();
        var mySecretKey = me.secretKey();
        var myIv = me.ivParameterSpec();
        var otherName = received.header().get("From");

        if (Protocol.DEFAULT_PREFIX.equals(received.prefix())) {
            var os = client.getOutputStream();
            var methodString = received.method().toString();

            if (methodString.startsWith("KEYXCHG")) {
                var response = new Protocol();
                var myPubKey = me.publicKey();
                var myPrivateKey = context.getPrivateKey();

                var algoString = received.header().get("Algo");
                var otherAlgo = Algorithm.valueOf(algoString);

                switch (received.method()) {
                    case KEYXCHG -> {
                        switch (otherAlgo) {
                            case RSA -> {
                                var receivedPubString = received.body().get(0);
                                var receivedPubKey = RSA.parsePublicKey(receivedPubString);

                                youMap.put(otherName, new User(
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
                                    RSA.toEncodedString(myPubKey),
                                    RSA.encrypt(mySecretKey.getEncoded(), receivedPubKey),
                                    RSA.encrypt(myIv.getIV(), receivedPubKey)
                                );
                            } 
                            case AES256CBC -> {
                                var receivedSecString = received.body().get(0);
                                var receivedIvString = received.body().get(1);
                                var decryptedSecBytes = RSA.decrypt(receivedSecString, myPrivateKey);
                                var decryptedIvBytes = RSA.decrypt(receivedIvString, myPrivateKey);

                                var receivedPubKey = youMap.get(otherName).publicKey();
                                var receivedSecKey = AES.parseSecretKey(decryptedSecBytes);
                                var receivedIv = AES.parseIv(decryptedIvBytes);

                                youMap.put(otherName, new User(
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
                                var decryptedSecBytes = RSA.decrypt(receivedSecString, myPrivateKey);
                                var decryptedIvBytes = RSA.decrypt(receivedIvString, myPrivateKey);

                                var receivedPubKey = RSA.parsePublicKey(receivedPubString);
                                var receivedSecKey = AES.parseSecretKey(decryptedSecBytes);
                                var receivedIv = AES.parseIv(decryptedIvBytes);

                                youMap.put(otherName, new User(
                                    otherName,
                                    receivedPubKey,
                                    receivedSecKey,
                                    receivedIv
                                ));

                                response = Protocol.algoProtocol(
                                    Method.KEYXCHG, 
                                    Algorithm.AES256CBC,
                                    me.name(), 
                                    otherName, 
                                    RSA.encrypt(mySecretKey.getEncoded(), receivedPubKey),
                                    RSA.encrypt(myIv.getIV(), receivedPubKey)
                                );
                            }
                            case AES256CBC -> {
                                context.setState(new TALKING(otherName));
                            }
                            default -> {}
                        }
                        if (otherAlgo == Algorithm.RSA) {
                        }
                    }
                    case KEYXCHGFAIL -> {
                        response = Protocol.algoProtocol(
                            Method.KEYXCHGRST, 
                            Algorithm.RSA, 
                            me.name(), 
                            otherName, 
                            RSA.toEncodedString(myPubKey)
                        );
                    }
                    case KEYXCHGRST -> {
                        var receivedPubString = received.body().get(0);
                        var receivedPubKey = RSA.parsePublicKey(receivedPubString);

                        youMap.put(otherName, new User(
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
                            RSA.toEncodedString(myPubKey),
                            RSA.encrypt(mySecretKey.getEncoded(), receivedPubKey),
                            RSA.encrypt(myIv.getIV(), receivedPubKey)
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
                var you = context.getYouMap().get(otherName);
                var decrypted = AES.decrypt(message, you);

                IO.print("\r\033[K");
                IO.println("%s: %s".formatted(otherName, decrypted));
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
