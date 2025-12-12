import 'dart:io';
import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';

class DataVulnerabilities {
  
  // Vulnerability 7: Sensitive Data in Logs
  static void logSensitiveData(String creditCard, String ssn) {
    // Logging sensitive information that could be exposed
    print('Processing payment for card: $creditCard, SSN: $ssn');
    print('Debug: User credentials - CC: $creditCard');
  }

  // Vulnerability 8: Insecure Data Storage
  static Future<void> storeDataInsecurely(String password, String apiKey) async {
    final prefs = await SharedPreferences.getInstance();
    // Storing sensitive data in plain text
    await prefs.setString('user_password', password);
    await prefs.setString('api_secret', apiKey);
    await prefs.setString('credit_card', '4532-1234-5678-9012');
  }

  // Vulnerability 9: Information Disclosure in Error Messages
  static String processUserData(String input) {
    try {
      final data = jsonDecode(input);
      return data['result'];
    } catch (e) {
      // Exposing internal system information in error messages
      return 'Database connection failed: server=prod-db-01.internal.company.com, '
             'user=admin, error=$e, input=$input';
    }
  }

  // Vulnerability 10: Race Condition in File Operations
  static Future<void> unsafeFileOperation(String filename, String content) async {
    final file = File(filename);
    // Race condition: checking existence and writing are separate operations
    if (!await file.exists()) {
      await Future.delayed(Duration(milliseconds: 100)); // Simulating delay
      await file.writeAsString(content); // Another process could create file here
    }
  }

  // Vulnerability 11: Directory Traversal in File Operations
  static Future<String> readUserFile(String userPath) async {
    // Directly using user input for file path without sanitization
    final file = File('/app/data/$userPath');
    try {
      return await file.readAsString();
    } catch (e) {
      return 'Error reading file: $userPath - $e';
    }
  }

  // Vulnerability 12: Insecure Random Token Generation
  static String generateInsecureToken() {
    // Using predictable random number generation for security tokens
    final random = DateTime.now().millisecondsSinceEpoch;
    return 'token_${random}_${random * 2}';
  }
}