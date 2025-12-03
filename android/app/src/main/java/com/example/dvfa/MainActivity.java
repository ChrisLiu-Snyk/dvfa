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

public class MainActivity extends FlutterActivity {
    private SQLiteDatabase db; // Declare SQLiteDatabase instance

    // Vulnerability: Hardcoded Credentials
    // Hardcoding sensitive credentials directly in the source code.
    private static final String HARDCODED_USERNAME = "dev_admin";
    private static final String HARDCODED_PASSWORD = "dev_password123!";

    // Vulnerability: Weak Hashing Algorithm
    // A custom, intentionally weak hashing algorithm for demonstration purposes.
    private String insecureHash(String input) {
        int hashValue = 0;
        for (int i = 0; i < input.length(); i++) {
            hashValue = (hashValue + input.charAt(i) * 31) ^ (hashValue >> 2);
        }
        return Integer.toHexString(hashValue);
    }

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Log.e("MyApp", "Using hardcoded credentials - Username: " + HARDCODED_USERNAME + ", Password: " + HARDCODED_PASSWORD);

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
