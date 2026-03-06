import java.io.*;
import java.net.*;
import java.sql.*;
import java.util.logging.*;
import java.security.*;
import javax.crypto.*;
import javax.xml.parsers.*;
import org.xml.sax.InputSource;

/**
 * SemgrepTestCases.java
 * Comprehensive Java test file for Semgrep vulnerability scanner.
 * Covers: OWASP Top 10, r2c-security-audit, p/java rulesets.
 *
 * WARNING: This file contains intentionally vulnerable code for testing purposes only.
 * DO NOT use in production.
 */
public class SemgrepTestCases {

    private static final Logger logger = Logger.getLogger("SemgrepTest");

    // -------------------------------------------------------
    // 1. HARDCODED CREDENTIALS
    // Rules: java.lang.security.hardcoded-credentials
    // -------------------------------------------------------
    public void hardcodedCredentials() {
        String password     = "admin123";
        String apiKey       = "sk-abc123xyz456secret";
        String awsSecret    = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        String dbUrl        = "jdbc:mysql://localhost/db?user=root&password=root";
        String jwtSecret    = "mysupersecretjwtkey";
    }

    // -------------------------------------------------------
    // 2. SQL INJECTION
    // Rules: java.lang.security.sql-injection
    // -------------------------------------------------------
    public void sqlInjection(Connection connection, String userId) throws SQLException {
        // Vulnerable: string concatenation in query
        String query = "SELECT * FROM users WHERE id = " + userId;
        Statement stmt = connection.createStatement();
        stmt.executeQuery(query);

        // Vulnerable: PreparedStatement used incorrectly
        Statement stmt2 = connection.createStatement();
        stmt2.execute("DELETE FROM orders WHERE user = '" + userId + "'");

        // Vulnerable: named query built dynamically
        String name = "admin' OR '1'='1";
        String q = "SELECT * FROM accounts WHERE username = '" + name + "'";
        connection.createStatement().executeQuery(q);
    }

    // -------------------------------------------------------
    // 3. COMMAND INJECTION
    // Rules: java.lang.security.command-injection
    // -------------------------------------------------------
    public void commandInjection(String userInput) throws IOException {
        // Vulnerable: Runtime.exec with user input
        Runtime.getRuntime().exec("ping " + userInput);

        // Vulnerable: ProcessBuilder with user-controlled args
        ProcessBuilder pb = new ProcessBuilder("bash", "-c", userInput);
        pb.start();

        // Vulnerable: shell command via array
        String[] cmd = {"/bin/sh", "-c", "ls " + userInput};
        Runtime.getRuntime().exec(cmd);
    }

    // -------------------------------------------------------
    // 4. PATH TRAVERSAL
    // Rules: java.lang.security.path-traversal
    // -------------------------------------------------------
    public void pathTraversal(String userInput) throws IOException {
        // Vulnerable: direct file path from user input
        File file = new File("/uploads/" + userInput);
        FileInputStream fis = new FileInputStream(userInput);

        // Vulnerable: file read without sanitization
        BufferedReader br = new BufferedReader(new FileReader("/var/data/" + userInput));
        br.readLine();
        br.close();
    }

    // -------------------------------------------------------
    // 5. INSECURE DESERIALIZATION
    // Rules: java.lang.security.insecure-deserialization
    // -------------------------------------------------------
    public void insecureDeserialization(InputStream inputStream) throws Exception {
        // Vulnerable: deserializing untrusted data
        ObjectInputStream ois = new ObjectInputStream(inputStream);
        Object obj = ois.readObject();

        // Vulnerable: custom ObjectInputStream without validation
        ObjectInputStream ois2 = new ObjectInputStream(new ByteArrayInputStream(new byte[0]));
        ois2.readObject();
    }

    // -------------------------------------------------------
    // 6. WEAK CRYPTOGRAPHY
    // Rules: java.lang.security.weak-crypto
    // -------------------------------------------------------
    public void weakCryptography(String password) throws Exception {
        // Vulnerable: MD5
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        md5.update(password.getBytes());

        // Vulnerable: SHA-1
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        sha1.update(password.getBytes());

        // Vulnerable: DES cipher
        Cipher des = Cipher.getInstance("DES");

        // Vulnerable: RC4
        Cipher rc4 = Cipher.getInstance("RC4");

        // Vulnerable: weak RSA without padding
        Cipher rsa = Cipher.getInstance("RSA/ECB/NoPadding");
    }

    // -------------------------------------------------------
    // 7. XXE - XML EXTERNAL ENTITY INJECTION
    // Rules: java.lang.security.xxe
    // -------------------------------------------------------
    public void xxeInjection(String xmlInput) throws Exception {
        // Vulnerable: DocumentBuilder without disabling external entities
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        db.parse(new InputSource(new StringReader(xmlInput)));

        // Vulnerable: SAXParser without security features
        SAXParserFactory spf = SAXParserFactory.newInstance();
        SAXParser sp = spf.newSAXParser();
    }

    // -------------------------------------------------------
    // 8. SSRF - SERVER-SIDE REQUEST FORGERY
    // Rules: java.lang.security.ssrf
    // -------------------------------------------------------
    public void ssrf(String userInput) throws IOException {
        // Vulnerable: user-controlled URL
        URL url = new URL(userInput);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.connect();

        // Vulnerable: opening stream from user input
        URL url2 = new URL(userInput);
        InputStream is = url2.openStream();
    }

    // -------------------------------------------------------
    // 9. XSS - CROSS-SITE SCRIPTING (Servlet context)
    // Rules: java.lang.security.xss
    // -------------------------------------------------------
    public void xss(javax.servlet.http.HttpServletRequest request,
                    javax.servlet.http.HttpServletResponse response) throws IOException {
        // Vulnerable: reflecting user input directly into response
        String name = request.getParameter("name");
        response.getWriter().println("<html>Welcome, " + name + "</html>");

        // Vulnerable: unescaped param in output
        String input = request.getParameter("input");
        response.getWriter().print(input);
    }

    // -------------------------------------------------------
    // 10. LOG INJECTION
    // Rules: java.lang.security.log-injection
    // -------------------------------------------------------
    public void logInjection(String userInput) {
        // Vulnerable: user input logged without sanitization
        logger.info("User action: " + userInput);
        logger.warning("Failed login for: " + userInput);
        logger.severe("Error caused by input: " + userInput);
    }

    // -------------------------------------------------------
    // 11. INSECURE RANDOM
    // Rules: java.lang.security.insecure-random
    // -------------------------------------------------------
    public void insecureRandom() {
        // Vulnerable: java.util.Random for security-sensitive use
        java.util.Random random = new java.util.Random();
        int token = random.nextInt();
        long sessionId = random.nextLong();
    }

    // -------------------------------------------------------
    // 12. OPEN REDIRECT
    // Rules: java.lang.security.open-redirect
    // -------------------------------------------------------
    public void openRedirect(javax.servlet.http.HttpServletRequest request,
                              javax.servlet.http.HttpServletResponse response) throws IOException {
        // Vulnerable: redirecting to user-supplied URL
        String redirectUrl = request.getParameter("redirect");
        response.sendRedirect(redirectUrl);
    }

    // -------------------------------------------------------
    // 13. LDAP INJECTION
    // Rules: java.lang.security.ldap-injection
    // -------------------------------------------------------
    public void ldapInjection(String userInput) throws Exception {
        // Vulnerable: user input in LDAP filter
        javax.naming.directory.InitialDirContext ctx =
            new javax.naming.directory.InitialDirContext();
        String filter = "(uid=" + userInput + ")";
        ctx.search("dc=example,dc=com", filter, null);
    }

    // -------------------------------------------------------
    // 14. TRUST BOUNDARY VIOLATION / HTTP HEADER INJECTION
    // Rules: java.lang.security.header-injection
    // -------------------------------------------------------
    public void headerInjection(javax.servlet.http.HttpServletRequest request,
                                 javax.servlet.http.HttpServletResponse response) {
        // Vulnerable: user input set in response header
        String lang = request.getParameter("lang");
        response.setHeader("Content-Language", lang);
    }

    // -------------------------------------------------------
    // 15. SENSITIVE DATA EXPOSURE
    // Rules: java.lang.security.sensitive-data-exposure
    // -------------------------------------------------------
    public void sensitiveDataExposure() {
        // Vulnerable: printing stack trace to user-facing output
        try {
            throw new Exception("Test");
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println(e.getMessage());
        }
    }

    public static void main(String[] args) {
        System.out.println("Semgrep Java Test Cases Loaded.");
    }
}
