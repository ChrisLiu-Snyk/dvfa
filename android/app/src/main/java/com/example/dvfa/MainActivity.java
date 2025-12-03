package com.example.dvfa;

import android.os.Bundle;
import android.os.Environment;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.net.http.SslError;
import android.webkit.SslErrorHandler;
import android.content.SharedPreferences;
import android.content.Context;
import java.util.Random;
import android.content.Intent;
import android.net.Uri;

import androidx.annotation.Nullable;

import java.io.File;

import io.flutter.embedding.android.FlutterActivity;
import io.flutter.plugin.common.BinaryMessenger;
import io.flutter.plugin.common.MethodChannel;
import android.database.sqlite.SQLiteDatabase; // Added for SQLiteDatabase
import android.content.ContentValues; // Added for ContentValues
import android.util.Log; // Added for Log
import android.app.PendingIntent; // Added for PendingIntent
import java.security.MessageDigest; // Added for MessageDigest
import java.security.NoSuchAlgorithmException; // Added for NoSuchAlgorithmException
import javax.net.ssl.HttpsURLConnection; // Added for HttpsURLConnection
import javax.net.ssl.SSLContext; // Added for SSLContext
import javax.net.ssl.TrustManager; // Added for TrustManager
import javax.net.ssl.X509TrustManager; // Added for X509TrustManager
import javax.net.ssl.HostnameVerifier; // Added for HostnameVerifier
import javax.net.ssl.SSLSession; // Added for SSLSession
import android.widget.TextView; // Added for TextView
import android.widget.LinearLayout; // Added for LinearLayout
import android.view.ViewGroup; // Added for ViewGroup
import android.graphics.Color; // Added for Color
import java.security.cert.X509Certificate; // Added for X509Certificate
import java.security.SecureRandom; // Added for SecureRandom
import java.io.Serializable; // Added for Serializable
import java.io.ObjectInputStream; // Added for ObjectInputStream
import java.io.ByteArrayInputStream; // Added for ByteArrayInputStream
import java.util.Base64; // Added for Base64 (for encoding/decoding serializable object)
import android.webkit.WebSettings; // Added for WebSettings
import javax.crypto.Cipher; // Added for Cipher
import javax.crypto.spec.SecretKeySpec; // Added for SecretKeySpec

public class MainActivity extends FlutterActivity {
    private SQLiteDatabase db; // Declare SQLiteDatabase instance

    // Insecure JavaScript object to be exposed to WebView
    private class InsecureJsObject {
        @android.webkit.JavascriptInterface
        public void showToast(String toast) {
            // This method is exposed to JavaScript.
            // In a real vulnerability, this might trigger a more sensitive action.
            Log.e("InsecureJsObject", "JavaScript called showToast: " + toast);
        }
    }

    // Vulnerability: Unsafe Deserialization of Untrusted Data
    // A simple serializable class that can be used to demonstrate deserialization vulnerability.
    // In a real exploit, this class could have malicious code in its constructor/readObject.
    static class InsecureSerializableClass implements Serializable {
        public String command;
        private static final long serialVersionUID = 1L;

        public InsecureSerializableClass(String command) {
            this.command = command;
        }

        private void readObject(ObjectInputStream ois) throws java.io.IOException, ClassNotFoundException {
            ois.defaultReadObject();
            // This is the point of vulnerability: executing a command from deserialized data.
            // In a real exploit, this would be more subtle, e.g., calling a dangerous method.
            Log.e("InsecureDeserialization", "Deserialized command: " + command);
            if (command != null && !command.isEmpty()) {
                try {
                    Runtime.getRuntime().exec(command);
                    Log.e("InsecureDeserialization", "Command executed: " + command);
                } catch (Exception e) {
                    Log.e("InsecureDeserialization", "Error executing command: " + e.getMessage());
                }
            }
        }
    }

    // Vulnerability: Hardcoded Credentials
    // Hardcoding sensitive credentials directly in the source code.
    private static final String HARDCODED_USERNAME = "dev_admin";
    private static final String HARDCODED_PASSWORD = "dev_password123!";

    // Vulnerability: Hardcoded Sensitive Information (Generic)
    // Another instance of hardcoded sensitive data directly in the code.
    private static final String GENERIC_SECRET_TOKEN = "ANOTHER_SUPER_SECRET_GENERIC_TOKEN";

    // Vulnerability: Weak Hashing Algorithm
    // A custom, intentionally weak hashing algorithm for demonstration purposes.
    private String insecureHash(String input) {
        int hashValue = 0;
        for (int i = 0; i < input.length(); i++) {
            hashValue = (hashValue + input.charAt(i) * 31) ^ (hashValue >> 2);
        }
        return Integer.toHexString(hashValue);
    }

    // Vulnerability: Use of Deprecated/Insecure Cryptography APIs (MD5)
    // Using MD5 for hashing, which is cryptographically insecure for many purposes.
    private String insecureMd5Hash(String input) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            md.update(input.getBytes());
            byte[] digest = md.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            Log.e("MyApp", "MD5 Hashing error: " + e.getMessage());
            return null;
        }
    }

    // Vulnerability: Weak Encryption (Custom XOR/Shift cipher)
    // A custom, insecure encryption algorithm using XOR and bit shifts.
    private String weakEncrypt(String data, String key) {
        StringBuilder encrypted = new StringBuilder();
        for (int i = 0; i < data.length(); i++) {
            char dataChar = data.charAt(i);
            char keyChar = key.charAt(i % key.length());
            char encryptedChar = (char) ((dataChar ^ keyChar) + 1); // Simple XOR and shift
            encrypted.append(encryptedChar);
        }
        return encrypted.toString();
    }

    // Vulnerability: Hardcoded Cryptographic Algorithm in Cipher.getInstance()
    // Using a hardcoded, insecure cryptographic algorithm (DES/ECB/PKCS5Padding).
    private void insecureCipherUsage() {
        try {
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("DES/ECB/PKCS5Padding"); // Insecure algorithm
            byte[] keyBytes = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}; // Example weak key
            javax.crypto.spec.SecretKeySpec secretKeySpec = new javax.crypto.spec.SecretKeySpec(keyBytes, "DES");
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKeySpec);
            Log.e("MyApp", "Insecure Cipher initialized: " + cipher.getAlgorithm());
        } catch (java.security.NoSuchAlgorithmException | javax.crypto.NoSuchPaddingException | java.security.InvalidKeyException e) {
            Log.e("MyApp", "Error with insecure cipher usage: " + e.getMessage());
        }
    }

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Call the insecure cipher usage method
        insecureCipherUsage();

        // Vulnerability: Sensitive Data Exposure in UI (TextView)
        // Exposing sensitive information directly in a TextView, which can be easily viewed.
        TextView sensitiveTextView = new TextView(this);
        sensitiveTextView.setText("Sensitive UI Data: user_session_id_ABCDEF");
        sensitiveTextView.setTextColor(Color.RED);
        // In a real app, this TextView would be added to the layout.
        // For demonstration, we just log its content to simulate exposure.
        Log.e("MyApp", "Sensitive data in UI (TextView): " + sensitiveTextView.getText().toString());

        // Using the weak custom encryption
        String sensitivePlainText = "my_sensitive_message";
        String encryptionKey = "weakkey";
        String encryptedData = weakEncrypt(sensitivePlainText, encryptionKey);
        Log.e("MyApp", "Weakly encrypted data: " + encryptedData);

        // Vulnerability: Hardcoded Sensitive Information (Generic)
        // Another instance of hardcoded sensitive data directly in the code.
        final String GENERIC_SECRET_TOKEN = "SECRET_DEVELOPMENT_TOKEN_DO_NOT_USE_IN_PROD";
        Log.e("MyApp", "Using generic secret token: " + GENERIC_SECRET_TOKEN);

        // Vulnerability: Insecure Randomness (Cryptographically Weak java.util.Random)
        // Using java.util.Random for generating a security token, which is not cryptographically strong.
        Random insecureTokenGenerator = new Random();
        String securityToken = String.valueOf(insecureTokenGenerator.nextLong());
        Log.e("MyApp", "Insecurely generated security token: " + securityToken);

        // Using the insecure MD5 hash
        String dataToHashMd5 = "secret_data_for_md5";
        String md5Hash = insecureMd5Hash(dataToHashMd5);
        Log.e("MyApp", "Insecure MD5 hash: " + md5Hash);

        // Vulnerability: Broadcast Sensitive Information
        // Sending an implicit broadcast containing sensitive data, which can be intercepted by any receiver.
        Intent sensitiveBroadcastIntent = new Intent("com.example.dvfa.SENSITIVE_DATA_BROADCAST");
        sensitiveBroadcastIntent.putExtra("sensitive_key", "sensitive_value_123");
        sendBroadcast(sensitiveBroadcastIntent);
        Log.e("MyApp", "Implicit broadcast with sensitive data sent.");

        // Vulnerability: Unsafe PendingIntent Usage
        // Creating a PendingIntent without FLAG_IMMUTABLE, making it mutable and prone to injection.
        Intent insecureIntent = new Intent(this, MainActivity.class);
        PendingIntent insecurePendingIntent = PendingIntent.getActivity(
                this, 0, insecureIntent, 0); // No FLAG_IMMUTABLE
        Log.e("MyApp", "Insecure PendingIntent created: " + insecurePendingIntent.toString());

        Log.e("MyApp", "Using hardcoded credentials - Username: " + HARDCODED_USERNAME + ", Password: " + HARDCODED_PASSWORD);
        Log.e("MyApp", "Using generic secret token: " + GENERIC_SECRET_TOKEN);

        // Vulnerability: Unsafe Deserialization of Untrusted Data
        // Deserializing a crafted object from a Base64 encoded string.
        String base64EncodedMaliciousObject = ""; // This would typically come from untrusted input
        try {
            // For demonstration, let's create a benign object and serialize it
            InsecureSerializableClass benignObject = new InsecureSerializableClass("echo Hello");
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            java.io.ObjectOutputStream oos = new java.io.ObjectOutputStream(bos);
            oos.writeObject(benignObject);
            oos.flush();
            base64EncodedMaliciousObject = Base64.getEncoder().encodeToString(bos.toByteArray());
            oos.close();
            bos.close();

            byte[] data = Base64.getDecoder().decode(base64EncodedMaliciousObject);
            java.io.ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            Object obj = ois.readObject(); // Vulnerable point
            ois.close();
            Log.e("MyApp", "Deserialized object of type: " + obj.getClass().getName());
        } catch (Exception e) {
            Log.e("MyApp", "Unsafe Deserialization error: " + e.getMessage());
        }

        // Vulnerability: Improper Neutralization of Special Elements in Output (Log Forging)
        // Logging user-controlled input directly without sanitization, allowing for log forging attacks.
        String userProvidedLog = "user_input_from_web_request%0aCRITICAL_ERROR: Unauthorized access attempt!";
        Log.e("MyApp", "User activity: " + userProvidedLog); // Log forging vulnerability

        // Using the weak hashing algorithm for a simulated password hash
        String sensitiveDataToHash = "myVerySecretPassword123";
        String hashedSensitiveData = insecureHash(sensitiveDataToHash);
        Log.e("MyApp", "Insecurely hashed data: " + hashedSensitiveData);

        // Vulnerability: Insecure Communication (HTTP client without SSL)
        // Making an HTTP request without SSL/TLS, exposing data to eavesdropping.
        try {
            java.net.URL url = new java.net.URL("http://insecure.example.com/api/data");
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            int responseCode = conn.getResponseCode();
            Log.e("MyApp", "Insecure HTTP request response code: " + responseCode);
            conn.disconnect();
        } catch (java.io.IOException e) {
            Log.e("MyApp", "Error making insecure HTTP request: " + e.getMessage());
        }

        // Vulnerability: Improper Certificate Validation (HostnameVerifier bypass)
        // Bypassing hostname verification for HttpsURLConnection, making it vulnerable to MITM.
        try {
            // Create a trust manager that does not validate certificate chains
            TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                }
            };
            // Install the all-trusting SSL context
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            // Create all-trusting host name verifier
            HostnameVerifier allHostsValid = new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    return true; // Always true, insecure
                }
            };
            // Install the all-trusting host verifier
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);

            java.net.URL httpsUrl = new java.net.URL("https://untrusted.example.com/sensitive_data");
            HttpsURLConnection httpsConn = (HttpsURLConnection) httpsUrl.openConnection();
            httpsConn.setRequestMethod("GET");
            int httpsResponseCode = httpsConn.getResponseCode();
            Log.e("MyApp", "Insecure HTTPS (HostnameVerifier bypass) request response code: " + httpsResponseCode);
            httpsConn.disconnect();
        } catch (Exception e) {
            Log.e("MyApp", "Error with insecure HTTPS (HostnameVerifier bypass) request: " + e.getMessage());
        }

        // Vulnerability: Hardcoded Path (File access)
        // Accessing a file with a hardcoded, potentially sensitive, absolute path.
        String hardcodedSensitiveFilePath = "/data/local/temp/sensitive_config.txt";
        File hardcodedFile = new File(hardcodedSensitiveFilePath);
        try {
            if (hardcodedFile.exists()) {
                // For demonstration, just logging existence; in a real app, content might be read.
                Log.e("MyApp", "Accessed hardcoded sensitive file: " + hardcodedFile.getAbsolutePath());
            } else {
                Log.e("MyApp", "Hardcoded sensitive file does not exist: " + hardcodedFile.getAbsolutePath());
            }
        } catch (SecurityException e) {
            Log.e("MyApp", "Security error accessing hardcoded file: " + e.getMessage());
        }

        // Vulnerability: Sensitive Data in URL (Information Exposure)
        // Constructing a URL with sensitive data (e.g., API key, session ID) directly in the query parameters.
        String apiKey = "very_secret_api_key_123";
        String sensitiveUrl = "https://insecure.example.com/api/v1/data?apiKey=" + apiKey + "&sessionID=abc123def456";
        Log.e("MyApp", "Sensitive data exposed in URL: " + sensitiveUrl); // Information Exposure

        // Vulnerability: Insecure Temporary File Creation
        // Creating a temporary file with world-readable permissions, exposing its content.
        try {
            File tempFile = File.createTempFile("insecure_prefix", ".tmp", getCacheDir());
            tempFile.setReadable(true, false); // Make world-readable (insecure)
            java.io.FileWriter tempWriter = new java.io.FileWriter(tempFile);
            tempWriter.append("This is sensitive data in an insecure temporary file.");
            tempWriter.flush();
            tempWriter.close();
            Log.e("MyApp", "Insecure temporary file created: " + tempFile.getAbsolutePath());
        } catch (java.io.IOException e) {
            Log.e("MyApp", "Error creating insecure temporary file: " + e.getMessage());
        }

        // Initialize database for SQL injection demo
        db = openOrCreateDatabase("insecure_database.db", MODE_PRIVATE, null);
        db.execSQL("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");

        // Vulnerability: SQL Injection (via rawQuery)
        // Using SQLiteDatabase.rawQuery with unsanitized user input, leading to SQL Injection.
        String rawQueryUserInput = "admin' OR '1'='1"; // Example of a malicious input
        android.database.Cursor cursor = null;
        try {
            cursor = db.rawQuery("SELECT * FROM users WHERE username = '" + rawQueryUserInput + "'", null);
            if (cursor != null && cursor.moveToFirst()) {
                Log.e("MyApp", "SQL Injection (rawQuery) resulted in data: " + cursor.getString(cursor.getColumnIndexOrThrow("username")));
            }
        } catch (Exception e) {
            Log.e("MyApp", "SQL Injection (rawQuery) error: " + e.getMessage());
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }

        // Vulnerability: Client-side SQL Injection (via execSQL)
        // Directly executing a SQL query with unsanitized user input using execSQL, leading to SQL Injection.
        String execSqlUserInput = "admin'; DROP TABLE users; --"; // Example of a malicious input
        try {
            db.execSQL("INSERT INTO users (username, password) VALUES ('" + execSqlUserInput + "', 'password')");
            Log.e("MyApp", "SQL Injection (execSQL) attempted with: " + execSqlUserInput);
        } catch (Exception e) {
            Log.e("MyApp", "SQL Injection (execSQL) error: " + e.getMessage());
        }

        // Original Vulnerability: SQL Injection
        // Constructing a SQL query directly with unsanitized user input.
        String userInputSql = "admin' OR '1'='1"; // Example of a malicious input
        String unsafeQuery = "SELECT * FROM users WHERE username = '" + userInputSql + "' AND password = 'password'";
        // In a real app, this query would be executed against a database.
        android.util.Log.e("MyApp", "Simulated SQL Injection Query: " + unsafeQuery);

        // Vulnerability: Command Injection
        // Directly executing a system command with unsanitized user input.
        String userCommand = "ls -la"; // Could be "ls -la; rm -rf /" from user input
        try {
            Process process = Runtime.getRuntime().exec(userCommand);
            java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line + "\n");
            }
            int exitVal = process.waitFor();
            if (exitVal == 0) {
                Log.e("MyApp", "Command output: " + output.toString());
            } else {
                Log.e("MyApp", "Command failed with error: " + output.toString());
            }
        } catch (java.io.IOException | InterruptedException e) {
            Log.e("MyApp", "Command execution error: " + e.getMessage());
        }

        // Vulnerability: Insecure Data Storage - SharedPreferences
        // Storing sensitive data in SharedPreferences without encryption.
        SharedPreferences sharedPref = this.getSharedPreferences("insecure_prefs", Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = sharedPref.edit();
        editor.putString("sensitive_key", "my_super_secret_unencrypted_value");
        editor.apply();

        // Vulnerability: Sensitive Data Exposure in Logcat
        // Logging sensitive information directly to Logcat, which can be accessed by other applications.
        String sensitiveInfo = "user_password_123";
        android.util.Log.e("MyApp", "Exposing sensitive info: " + sensitiveInfo);

        // Vulnerability: Insecure Random Number Generation
        // Using java.util.Random for security-sensitive operations, which is not cryptographically secure.
        Random insecureRandom = new Random();
        int secretValue = insecureRandom.nextInt(); // Insecurely generated secret
        System.out.println("Insecurely generated secret: " + secretValue);

        // Vulnerability: External Storage Write Access
        // Writing sensitive data to external storage, which is publicly accessible.
        File externalFile = new File(Environment.getExternalStorageDirectory(), "sensitive_external_data.txt");
        try {
            java.io.FileWriter writer = new java.io.FileWriter(externalFile);
            writer.append("This is highly sensitive data written to external storage.");
            writer.flush();
            writer.close();
            android.util.Log.e("MyApp", "Sensitive data written to external storage: " + externalFile.getAbsolutePath());
        } catch (java.io.IOException e) {
            android.util.Log.e("MyApp", "Error writing to external storage: " + e.getMessage());
        }

        // Vulnerability: Untrusted Input in Intent
        // Creating an implicit Intent with an unsanitized URI from a hardcoded string, potentially allowing
        // malicious redirection or arbitrary component launching if the URI was user-controlled.
        String untrustedUriString = "http://insecure.example.com/malicious_redirect";
        Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(untrustedUriString));
        // In a real app, if this URI came from user input, it would be a critical vulnerability.
        startActivity(intent);

        // Vulnerability: Trusting All Certificates (Allowing All Hosts) in WebView
        // This configuration bypasses SSL certificate validation, making the WebView vulnerable to MITM attacks.
        WebView webView = new WebView(this);
        // Vulnerability: Insecure WebView Configuration - File Access Enabled
        // Enabling file access in a WebView can lead to local file disclosure if untrusted content is loaded.
        webView.getSettings().setAllowFileAccess(true); // WARNING: This line allows file access.

        // Vulnerability: WebView Remote Code Execution (RCE) / JavaScript Enabled
        // Enabling JavaScript and loading content from arbitrary URLs can lead to RCE if untrusted content is loaded.
        webView.getSettings().setJavaScriptEnabled(true); // WARNING: Enables JavaScript
        webView.loadUrl("http://insecure.example.com/malicious_script.html"); // WARNING: Loading from untrusted source

        // Vulnerability: Unsafe WebView Asset Loading
        // Loading local files directly into a WebView without proper security checks can lead to local file exposure.
        // For demonstration, loading a sensitive local file directly.
        webView.loadUrl("file:///data/data/com.example.dvfa/shared_prefs/insecure_prefs.xml"); // WARNING: Exposes sensitive local file

        // Vulnerability: Insecure WebView Configuration - Mixed Content
        // Allowing mixed content (HTTP and HTTPS) in WebView can lead to insecure data transmission and MITM attacks.
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.LOLLIPOP) {
            webView.getSettings().setMixedContentMode(android.webkit.WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
            Log.e("MyApp", "WebView mixed content mode set to ALWAYS_ALLOW (insecure)");
        }

        // Vulnerability: Insecure WebView addJavascriptInterface()
        // Exposing a Java object to JavaScript without proper security, enabling RCE from untrusted web content.
        webView.addJavascriptInterface(new InsecureJsObject(), "Android");
        Log.e("MyApp", "Insecure JavaScript interface 'Android' added to WebView.");

        // Vulnerability: Sensitive Data Exposure in UI (TextView)
        // Exposing sensitive information directly in a TextView, which can be easily viewed.
        TextView sensitiveTextView = new TextView(this);
        sensitiveTextView.setText("Sensitive UI Data: user_session_id_ABCDEF");
        sensitiveTextView.setTextColor(Color.RED);
        // In a real app, this TextView would be added to the layout.
        // For demonstration, we just log its content to simulate exposure.
        Log.e("MyApp", "Sensitive data in UI (TextView): " + sensitiveTextView.getText().toString());

        // Vulnerability: Unsafe PendingIntent Usage
        // Creating a PendingIntent without FLAG_IMMUTABLE, making it mutable and prone to injection.
        Intent insecurePendingIntent = new Intent(this, MainActivity.class);
        PendingIntent mutablePendingIntent = PendingIntent.getActivity(
                this, 0, insecurePendingIntent, 0); // FLAG_IMMUTABLE is missing
        Log.e("MyApp", "Mutable PendingIntent created (Vulnerable): " + mutablePendingIntent.toString());

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
                handler.proceed(); // WARNING: This line allows all SSL certificates, disabling security.
            }
        });
        // For demonstration, you might load an insecure URL or some content
        // webView.loadUrl("https://untrusted.example.com");

        final BinaryMessenger messenger = getFlutterEngine().getDartExecutor().getBinaryMessenger();
        new MethodChannel(messenger, "app").setMethodCallHandler(
                (call, result) -> {
                    if (call.method.equalsIgnoreCase("saveText")) {
                        String userDefinedFile = call.argument("fileName");
                        // Vulnerability: Improper Input Validation (MethodChannel argument)
                        // Directly using user-provided fileName without validation, leading to potential path traversal or other issues.
                        Log.e("MyApp", "Processing file with unvalidated name from MethodChannel: " + userDefinedFile);

                        // Vulnerability: Path Traversal (Android Native)
                        // Directly using user input in a file path without sanitization, leading to path traversal.
                        File newFile = new File(Environment.getExternalStorageDirectory(), userDefinedFile);
                        try {
                            // This could create or overwrite files outside the intended directory.
                            java.io.FileWriter writer = new java.io.FileWriter(newFile);
                            writer.append("Data for file: " + userDefinedFile);
                            writer.flush();
                            writer.close();
                            Log.e("MyApp", "File created via path traversal: " + newFile.getAbsolutePath());
                            result.success(true);
                        } catch (java.io.IOException e) {
                            Log.e("MyApp", "Error in path traversal file write: " + e.getMessage());
                            result.success(false);
                        }
                    }
                }
        );
    }
}
