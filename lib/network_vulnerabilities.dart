import 'dart:io';
import 'dart:convert';
import 'package:http/http.dart' as http;

class NetworkVulnerabilities {
  
  // Vulnerability 1: Unvalidated Redirects and Forwards
  static Future<void> unsafeRedirect(String userUrl) async {
    // Directly redirecting to user-provided URL without validation
    final response = await http.get(Uri.parse(userUrl));
    print('Redirected to: $userUrl');
  }

  // Vulnerability 2: Server-Side Request Forgery (SSRF)
  static Future<void> ssrfVulnerability(String targetUrl) async {
    // Making requests to user-controlled URLs without validation
    try {
      final response = await http.get(Uri.parse('http://internal-service/$targetUrl'));
      print('SSRF Response: ${response.body}');
    } catch (e) {
      print('SSRF Error: $e');
    }
  }

  // Vulnerability 3: HTTP Response Splitting
  static String createUnsafeHeader(String userInput) {
    // Directly inserting user input into HTTP headers
    return 'Set-Cookie: sessionId=abc123\r\nContent-Type: text/html\r\n$userInput';
  }

  // Vulnerability 4: Insecure HTTP Methods
  static Future<void> unsafeHttpMethods(String data) async {
    // Using TRACE method which can lead to XST attacks
    final request = http.Request('TRACE', Uri.parse('https://example.com/api'));
    request.body = data;
    final response = await request.send();
    print('TRACE response: ${response.statusCode}');
  }

  // Vulnerability 5: Missing Security Headers
  static Map<String, String> getInsecureHeaders() {
    // Missing critical security headers
    return {
      'Content-Type': 'application/json',
      // Missing: X-Frame-Options, X-Content-Type-Options, etc.
    };
  }

  // Vulnerability 6: Weak TLS Configuration
  static HttpClient createInsecureHttpClient() {
    final client = HttpClient();
    // Vulnerability: Allowing weak TLS versions
    client.supportedProtocols = ['ssl', 'tls1.0', 'tls1.1']; // Weak protocols
    return client;
  }
}