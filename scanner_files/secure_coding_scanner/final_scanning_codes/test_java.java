import java.io.*;

public class test_java {

    public static void main(String[] args) {
        String password = "password123"; // Hardcoded password (FF1004)
        String xmlData = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>"; // XXE Injection (FF1012)
        String redirectUrl = "http://example.com/redirect?param=malicious"; // Unvalidated Redirects and Forwards (FF1013)

        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        try {
            String input = reader.readLine(); // Buffer Overflow (FF1001)
        } catch (IOException e) {
            e.printStackTrace();
        }

        Runtime.getRuntime().exec("echo Hello, world!"); // Command Injection (FF1003)

        String sqlQuery = "SELECT * FROM users WHERE username='" + args[0] + "'"; // SQL Injection (FF1005)

        String serializedData = "SerializedData"; // Insecure Deserialization (FF1006)
    }
}
