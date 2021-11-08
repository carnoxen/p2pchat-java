package main;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

public class E2EEChat
{
    private Socket clientSocket = null;
    private User me = new User();
    public State chatState = State.from;

    public Socket getSocketContext() {
        return clientSocket;
    }
    
    public User getMe() {
    	return me;
    }

    // 접속 정보, 필요시 수정
    private final String hostname = "homework.islab.work";
    private final int port = 8080;

    public E2EEChat() throws IOException {
       clientSocket = new Socket();
       clientSocket.connect(new InetSocketAddress(hostname, port));

       InputStream stream = clientSocket.getInputStream();

       Thread senderThread = new Thread(new MessageSender(this));
       senderThread.start();

       while (true) {
           try {
               if (clientSocket.isClosed() || !senderThread.isAlive()) {
                   break;
               }

               byte[] recvBytes = new byte[2048];
               int recvSize = stream.read(recvBytes);

               if (recvSize == 0) {
                   continue;
               }

               String recv = new String(recvBytes, 0, recvSize, StandardCharsets.UTF_8);

               parseReceiveData(recv);
           } catch (Exception ex) {
               System.out.println("소켓 데이터 수신 중 문제가 발생하였습니다.");
               break;
           }
       }

       try {
           System.out.println("입력 스레드가 종료될때까지 대기중...");
           senderThread.join();

           if (clientSocket.isConnected()) {
               clientSocket.close();
           }
       } catch (InterruptedException ex) {
           System.out.println("종료되었습니다.");
       }
    }

    public void parseReceiveData(String recvData) throws Exception {
        // 여기부터 3EPROTO 패킷 처리를 개시합니다.
        //System.out.println(recvData + "\n==== recv ====");
        Protocol p = Protocol.strToPro(recvData);
		Protocol rp = new Protocol();
        
        if (p.prefix.equals("3EPROTO")) {
        	var sockOut = clientSocket.getOutputStream();
        	
        	if (p.method.equals("DENY")) {
        		chatState = State.from;
        	}
        	else if(p.method.equals("KEYXCHG")) {
        		if (!me.yourPublickey.equals("")) {
        			rp.method = "KEYXCHGFAIL";
        			
        			rp.headerMap.put("From", me.myName);
        			
        			rp.bodyArray.add("Duplicated Key Exchange Request");
        		}
        		else if (p.headerMap.get("Algo").equals("RSA")) {
        			me.yourPublickey = p.bodyArray.get(0);
        			
        			rp.method = "KEYXCHGOK";
        			
        			rp.headerMap.put("Algo", "RSA");
        			rp.headerMap.put("From", me.myName);
        		}
        		else {
        			me.yourSecretKey = RSA.decrypt(p.bodyArray.get(0), me.myPrivateKey);
        			me.yourIv = RSA.decrypt(p.bodyArray.get(1), me.myPrivateKey);
        			
        			rp.method = "KEYXCHGOK";
        			
        			rp.headerMap.put("Algo", "AES-256-CBC");
        			rp.headerMap.put("From", me.myName);
        		}
    			
    			sockOut.write(rp.toString().getBytes());
    			sockOut.flush();
        	}
        	else if(p.method.equals("KEYXCHGOK")) {
        		if (p.headerMap.get("Algo").equals("RSA")) {
        			rp.method = "KEYXCHG";
        			
        			rp.headerMap.put("Algo", "AES-256-CBC");
        			rp.headerMap.put("From", me.myName);
        			rp.headerMap.put("To", me.yourName);
        			
        			rp.bodyArray.add(RSA.encrypt(me.mySecretKey, me.yourPublickey));
        			rp.bodyArray.add(RSA.encrypt(me.myIv, me.yourPublickey));
        			
        			sockOut.write(rp.toString().getBytes());
        			sockOut.flush();
        		}
        	}
        	else if(p.method.equals("KEYXCHGFAIL")) {
    			rp.method = "KEYXCHGRST";
            	
            	rp.headerMap.put("Algo", "RSA");
            	rp.headerMap.put("From", me.myName);
            	rp.headerMap.put("To", me.yourName);
            	
            	rp.bodyArray.add(me.myPublicKey);
    			
    			sockOut.write(rp.toString().getBytes());
    			sockOut.flush();
        	}
        	else if(p.method.equals("KEYXCHGRST")) {
        		me.yourPublickey = p.bodyArray.get(0);
        		
    			rp.method = "KEYXCHGOK";

            	rp.headerMap.put("Algo", "RSA");
    			rp.headerMap.put("From", me.myName);
    			
    			sockOut.write(rp.toString().getBytes());
    			sockOut.flush();
        	}
        	else if(p.method.equals("MSGRECV")) {
        		String decrypted = AES.decrypt(p.bodyArray.get(0), me.yourSecretKey, me.yourIv);
        		String from = p.headerMap.get("From");
        		System.out.println(String.format("%s>%s", from, decrypted));
        	}
        }
        else {}
    }

    // 필요한 경우 추가로 메서드를 정의하여 사용합니다.

//    public static void main(String[] args)
//    {
//        try {
//            new E2EEChat();
//        } catch (UnknownHostException ex) {
//            System.out.println("연결 실패, 호스트 정보를 확인하세요.");
//        } catch (IOException ex) {
//            System.out.println("소켓 통신 중 문제가 발생하였습니다.");
//        }
//    }
}

// 사용자 입력을 통한 메세지 전송을 위한 Sender Runnable Class
// 여기에서 메세지 전송 처리를 수행합니다.
class MessageSender implements Runnable {
    E2EEChat clientContext;
    OutputStream socketOutputStream;

    public MessageSender(E2EEChat context) throws IOException {
        clientContext = context;

        Socket clientSocket = clientContext.getSocketContext();
        socketOutputStream = clientSocket.getOutputStream();
    }

    @Override
    public void run() {
        Scanner scanner = new Scanner(System.in);

        while (true) {
            try {
                var cs = clientContext.chatState;
            	User me = clientContext.getMe();
                Protocol p = new Protocol();
                
            	if (cs == State.from) {
                    System.out.print("type your name: ");
            	}
            	else if (cs == State.to) {
            		System.out.print("type to: ");
            	}
            	else {
            		System.out.print(me.myName + '>');
            	}

                String message = scanner.nextLine().trim();
                
                if (cs == State.from) {
                	clientContext.chatState = State.to;
                	me.myName = message;
                	p.method = "CONNECT";
                	p.headerMap.put("Credential", message);
                	
                	String[] keyPair = RSA.getKeyPair();
                	me.myPublicKey = keyPair[0];
                	me.myPrivateKey = keyPair[1];
                	
                	String[] keySet = AES.getKeySet();
                	me.mySecretKey = keySet[0];
                	me.myIv = keySet[1];
                }
                else if (cs == State.to) {
                	clientContext.chatState = State.message;
                	me.yourName = message;
                	p.method = "KEYXCHG";
                	
                	p.headerMap.put("Algo", "RSA");
                	p.headerMap.put("From", me.myName);
                	p.headerMap.put("To", me.yourName);
                	
                	p.bodyArray.add(me.myPublicKey);
                }
                else if(message.equals("disconnect")) {
                	p.method = "DISCONNECT";
                	
                	p.headerMap.put("Credential", me.myName);
                	clientContext.chatState = State.from;
                }
                else {
                	p.method = "MSGSEND";
                	
                	p.headerMap.put("From", me.myName);
                	p.headerMap.put("To", message);
                	byte[] b = new byte[4];
                	new SecureRandom().nextBytes(b);
                	String nonceString = Base64.getEncoder().encodeToString(b).substring(0, 5);
                	p.headerMap.put("Nonce", nonceString);
                	
                	p.bodyArray.add(AES.encrypt(message, me.mySecretKey, me.myIv));
                }
                
                byte[] payload = p.toString().getBytes(StandardCharsets.UTF_8);

                socketOutputStream.write(payload, 0, payload.length);
                socketOutputStream.flush();
            } catch (Exception ex) {
                break;
            }
        }

        System.out.println("MessageSender runnable end");
        scanner.close();
    }
}