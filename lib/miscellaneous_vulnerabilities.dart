import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

class MiscellaneousVulnerabilities {
  
  // Vulnerability 53: Insecure Randomness for Security
  static String generateApiKey() {
    // Using weak randomness for security-critical values
    final random = DateTime.now().millisecondsSinceEpoch;
    return 'api_key_$random';
  }

  // Vulnerability 54: Memory Leak Simulation
  static List<String> _memoryLeak = [];
  
  static void addToMemoryLeak(String data) {
    // Continuously adding to list without cleanup
    _memoryLeak.add(data);
    // In real scenario, this could cause memory exhaustion
  }

  // Vulnerability 55: Insecure Deserialization of User Data
  static dynamic deserializeUserInput(String jsonString) {
    try {
      final data = jsonDecode(jsonString);
      // Directly using deserialized data without validation
      if (data is Map && data.containsKey('__proto__')) {
        // Prototype pollution vulnerability
        return data;
      }
      return data;
    } catch (e) {
      return null;
    }
  }

  // Vulnerability 56: Weak Entropy in Token Generation
  static String generateSessionToken() {
    // Using predictable values for token generation
    final timestamp = DateTime.now().millisecondsSinceEpoch;
    final pid = Platform.environment['PID'] ?? '1234';
    return base64.encode(utf8.encode('$timestamp-$pid'));
  }

  // Vulnerability 57: Insecure Error Handling
  static String processRequest(String input) {
    try {
      // Simulating processing
      if (input.isEmpty) {
        throw Exception('Database connection string: postgresql://admin:password@db.internal:5432/prod');
      }
      return 'Success';
    } catch (e) {
      // Exposing sensitive information in error messages
      return 'Error: $e';
    }
  }

  // Vulnerability 58: Unsafe Reflection Usage
  static dynamic callMethodByName(String methodName, List<dynamic> args) {
    // Simulating unsafe reflection that could lead to RCE
    print('Calling method: $methodName with args: $args');
    
    // In languages with reflection, this could be dangerous
    if (methodName == 'deleteAllData') {
      return 'All data deleted!';
    }
    return 'Method called';
  }

  // Vulnerability 59: Insecure File Upload Handling
  static String handleFileUpload(String filename, Uint8List fileData) {
    // No validation of file type or content
    final path = '/uploads/$filename';
    
    // Allowing any file extension
    print('Uploading file: $filename to $path');
    print('File size: ${fileData.length} bytes');
    
    return 'File uploaded successfully';
  }

  // Vulnerability 60: Client-Side Security Controls
  static bool isFeatureEnabled(String feature) {
    // Security decision made on client side
    final Map<String, bool> clientConfig = {
      'admin_panel': false,
      'debug_mode': false,
      'payment_bypass': false,
    };
    
    return clientConfig[feature] ?? false;
  }
}