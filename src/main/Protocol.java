package main;

import java.util.HashMap;
import java.util.ArrayList;
import java.util.Scanner;

public class Protocol {
	public String prefix = "3EPROTO", method = "";
	public HashMap<String, String> headerMap = new HashMap<>();
	public ArrayList<String> bodyArray = new ArrayList<>();
	
	public String toString() {
		String res = "";
		
		res += prefix + ' ' + method + '\n';
		
		for (String c : headerMap.keySet()) {
			res += (c + ':' + headerMap.get(c) + '\n');
		}
		
		res += '\n';
		
		for (String c : bodyArray) {
			res += (c + '\n');
		}
		
		return res;
	}
	
	public static Protocol strToPro(String s) {
		Protocol p = new Protocol();
		
		Scanner scanner = new Scanner(s);
		
		String lined = scanner.nextLine();
		String[] s_pre = lined.split(" ");
		p.prefix = s_pre[0];
		p.method = s_pre[1];
		
		while (!(lined = scanner.nextLine()).equals("")) {
			int index = lined.indexOf((int) ':');
			
			String name = lined.substring(0, index);
			String value = lined.substring(index + 1).trim();
			
			p.headerMap.put(name, value);
		}
		
		while (scanner.hasNextLine()) {
			lined = scanner.nextLine();
			p.bodyArray.add(lined);
		}
		
		scanner.close();
		return p;
	}
}
