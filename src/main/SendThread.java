package main;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

public class SendThread implements Runnable {
    private SocketContext context;

    public SendThread(SocketContext context) {
        this.context = context;
    }

    private Protocol sendConnect(User me) {
        Protocol p = new Protocol();

        p.method = "CONNECT";
        p.headerMap.put("Credential", me.myName);

        return p;
    }

    private Protocol sendDisconnect(User me) {
        Protocol p = new Protocol();

        p.method = "DISCONNECT";
        p.headerMap.put("Credential", me.myName);

        return p;
    }

    private Protocol sendKeyexc(User me) {
        Protocol p = new Protocol();

        p.method = "KEYXCHG";

        p.headerMap.put("Algo", "RSA");
        p.headerMap.put("From", me.myName);
        p.headerMap.put("To", me.yourName);

        p.bodyArray.add(me.myPublicKey);

        return p;
    }

    private Protocol sendMessage(User me, String message) throws Exception {
        Protocol p = new Protocol();

        p.method = "MSGSEND";

        p.headerMap.put("From", me.myName);
        p.headerMap.put("To", me.yourName);
        byte[] b = new byte[4];
        new SecureRandom().nextBytes(b);
        String nonceString = Base64.getEncoder().encodeToString(b).substring(0, 5);
        p.headerMap.put("Nonce", nonceString);

        p.bodyArray.add(AES.encrypt(message, me.mySecretKey, me.myIv));

        return p;
    }

    private User createUser(String name) throws NoSuchAlgorithmException {
        User u = new User();
        u.myName = name;

        String[] keyPair = RSA.getKeyPair();
        u.myPublicKey = keyPair[0];
        u.myPrivateKey = keyPair[1];

        String[] keySet = AES.getKeySet();
        u.mySecretKey = keySet[0];
        u.myIv = keySet[1];

        return u;
    }

    @Override
    public void run() {
        // TODO Auto-generated method stub
        var scanner = new Scanner(System.in);

        while (!context.getClientSocket().isClosed()) {
            try {
                var os = context.getClientSocket().getOutputStream();

                // var cs = context.getState();
                User me = context.getMe();
                Protocol p = new Protocol();

                System.out.print("> ");
                String command = scanner.nextLine().trim();

                if (command.equals("connect")) {
                    String name = scanner.nextLine().trim();

                    me = createUser(name);

                    p = sendConnect(me);
                } else if (command.equals("disconnect")) {
                    p = sendDisconnect(me);
                } else if (command.equals("keyexc")) {
                    String name = scanner.nextLine().trim();

                    me.yourName = name;

                    p = sendKeyexc(me);
                } else {
                    p = sendMessage(me, command);
                }

                context.setMe(me);
                // System.out.print("\r==== send ====\n" + p.toString() + "\n==== send ====\n>
                // ");

                byte[] payload = p.toString().getBytes(StandardCharsets.UTF_8);

                os.write(payload, 0, payload.length);
                os.flush();
            } catch (Exception e) {
                System.out.println(e);
                scanner.close();
                break;
            }
        }
    }

}
