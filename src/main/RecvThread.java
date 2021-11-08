package main;

import java.nio.charset.StandardCharsets;

public class RecvThread implements Runnable {
	private SocketContext context;
	
	public RecvThread(SocketContext context) {
		this.context = context;
	}

    public void parseReceiveData(String recvData) throws Exception {
        // 여기부터 3EPROTO 패킷 처리를 개시합니다.
        //System.out.print("\n==== recv ====\n" + recvData + "\n==== recv ====\n> ");
        Protocol p = Protocol.strToPro(recvData);
		Protocol rp = new Protocol();
		User me = context.getMe();
        
        if (p.prefix.equals("3EPROTO")) {
        	var sockOut = context.getClientSocket().getOutputStream();
        	
        	if(p.method.equals("KEYXCHG")) {
        		if (!me.yourPublickey.equals("") && context.getState() == State.from) {
        			rp.method = "KEYXCHGFAIL";

                	rp.headerMap.put("Algo", "RSA");
        			rp.headerMap.put("From", me.myName);
        			rp.headerMap.put("To", me.yourName);
        			
        			rp.bodyArray.add("Duplicated Key Exchange Request");
        		}
        		else if (p.headerMap.get("Algo").equals("RSA")) {
        			me.yourName = p.headerMap.get("From");
        			me.yourPublickey = p.bodyArray.get(0);
        			
        			rp.method = "KEYXCHGOK";
        			
        			rp.headerMap.put("Algo", "RSA");
        			rp.headerMap.put("From", me.myName);
        			rp.headerMap.put("To", me.yourName);
        			
        			rp.bodyArray.add(me.myPublicKey);
        			rp.bodyArray.add(RSA.encrypt(me.mySecretKey, me.yourPublickey));
        			rp.bodyArray.add(RSA.encrypt(me.myIv, me.yourPublickey));
        			
        			context.setState(State.to);
        		}
        		else if (p.headerMap.get("Algo").equals("AES-256-CBC")) {
        			me.yourSecretKey = RSA.decrypt(p.bodyArray.get(0), me.myPrivateKey);
        			me.yourIv = RSA.decrypt(p.bodyArray.get(1), me.myPrivateKey);
        			
        			rp.method = "KEYXCHGOK";
        			
        			rp.headerMap.put("Algo", "AES-256-CBC");
        			rp.headerMap.put("From", me.myName);
        			rp.headerMap.put("To", me.yourName);
        		}
                //System.out.print("\n==== send ====\n" + rp.toString() + "\n==== send ====\n> ");
    			
    			sockOut.write(rp.toString().getBytes());
    			sockOut.flush();
        	}
        	else if(p.method.equals("KEYXCHGOK")) {
        		if (p.headerMap.get("Algo").equals("RSA")) {
        			me.yourPublickey = p.bodyArray.get(0);
        			me.yourSecretKey = RSA.decrypt(p.bodyArray.get(1), me.myPrivateKey);
        			me.yourIv = RSA.decrypt(p.bodyArray.get(2), me.myPrivateKey);
        			
        			rp.method = "KEYXCHG";
        			
        			rp.headerMap.put("Algo", "AES-256-CBC");
        			rp.headerMap.put("From", me.myName);
        			rp.headerMap.put("To", me.yourName);
        			
        			rp.bodyArray.add(RSA.encrypt(me.mySecretKey, me.yourPublickey));
        			rp.bodyArray.add(RSA.encrypt(me.myIv, me.yourPublickey));
        			
                    //System.out.print("\n==== send ====\n" + p.toString() + "\n==== send ====\n> ");
        			
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

                //System.out.print("\n==== send ====\n" + p.toString() + "\n==== send ====\n> ");
    			sockOut.write(rp.toString().getBytes());
    			sockOut.flush();
        	}
        	else if(p.method.equals("KEYXCHGRST")) {
        		me.yourPublickey = p.bodyArray.get(0);
        		
    			rp.method = "KEYXCHGOK";

            	rp.headerMap.put("Algo", "RSA");
    			rp.headerMap.put("From", me.myName);
    			rp.headerMap.put("To", me.yourName);

                //System.out.print("\n==== send ====\n" + p.toString() + "\n==== send ====\n> ");
    			sockOut.write(rp.toString().getBytes());
    			sockOut.flush();
        	}
        	else if(p.method.equals("MSGRECV")) {
        		String decrypted = AES.decrypt(p.bodyArray.get(0), me.yourSecretKey, me.yourIv);
        		String from = p.headerMap.get("From");
        		System.out.print(String.format("\r%s: %s\n> ", from, decrypted));
        	}
        }
        else {}
        
        context.setMe(me);
    }

	@Override
	public void run() {
		// TODO Auto-generated method stub
		while (!context.getClientSocket().isClosed()) {
			try {
					var is = context.getClientSocket().getInputStream();
					
					byte[] recvBytes = new byte[2048];
					
					int recvSize = is.read(recvBytes);
					
					if (recvSize == 0) {
					    continue;
					}
					
					String recv = new String(recvBytes, 0, recvSize, StandardCharsets.UTF_8);
					
					parseReceiveData(recv);
			}
			catch (Exception e) {
				System.out.println("\r" + e);
				break;
			}
		}
	}
}
