package main.protocol;

import java.security.SecureRandom;
import java.util.Scanner;

public record Protocol(
    String prefix,
    Method method,
    Header header,
    Body body
) {
    public static final String DEFAULT_PREFIX = "3EPROTO";

    @Override
    public String toString() {
        String fraction = """
                %s %s
                %s

                %s

                """.formatted(prefix, method.toString(), header, body);

        return fraction;
    }

    public static Protocol connProtocol(Method method, String from) {
        var aHeader = new Header() {{
            put("Credential", from);
        }};

        return new Protocol(
            DEFAULT_PREFIX,
            method,
            aHeader,
            null
        );
    }

    public static Protocol algoProtocol(Method method, String algorithm, String from, String to, String... strings) {
        var aHeader = new Header() {{
            put("Algo", algorithm);
            put("From", from);
            put("To", to);
        }};
        var aBody = new Body() {{
            for (var s: strings) {
                add(s);
            }
        }};

        return new Protocol(
            DEFAULT_PREFIX,
            method,
            aHeader,
            aBody
        );
    }

    public static Protocol msgProtocol(String from, String to, String... strings) {
        var random = new SecureRandom();
        var aHeader = new Header() {{
            put("From", from);
            put("To", to);
            put("Nonce", random.toString());
        }};
        var aBody = new Body() {{
            for (var s: strings) {
                add(s);
            }
        }};

        return new Protocol(
            DEFAULT_PREFIX,
            Method.MSGSEND,
            aHeader,
            aBody
        );
    }

    public static Protocol strToPro(String s) {
        Scanner scanner = new Scanner(s);
        Header aHeader = new Header();
        Body aBody = new Body();

        String lined = scanner.nextLine();
        String[] s_pre = lined.split(" ");
        String prefix = s_pre[0], method = s_pre[1];

        while (!(lined = scanner.nextLine()).equals("")) {
            int index = lined.indexOf((int) ':');

            String name = lined.substring(0, index);
            String value = lined.substring(index + 1).trim();

            aHeader.put(name, value);
        }

        while (scanner.hasNextLine()) {
            lined = scanner.nextLine();
            aBody.add(lined);
        }

        scanner.close();
        return new Protocol(prefix, Method.valueOf(method), aHeader, aBody);
    }
}
