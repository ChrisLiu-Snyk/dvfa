import 'dart:convert';
import 'dart:io';

class InputValidationVulnerabilities {
  
  // Vulnerability 36: Buffer Overflow Simulation
  static String processLargeInput(String input) {
    // No length validation - could cause memory issues
    final buffer = List<int>.filled(1024, 0);
    final inputBytes = utf8.encode(input);
    
    // Simulating buffer overflow by not checking bounds
    for (int i = 0; i < inputBytes.length; i++) {
      if (i < buffer.length) {
        buffer[i] = inputBytes[i];
      }
    }
    return String.fromCharCodes(buffer);
  }

  // Vulnerability 37: Format String Vulnerability
  static void logUserInput(String userInput) {
    // Directly using user input in format string
    print('User input: $userInput');
    // In C-style languages, this would be: printf(userInput);
  }

  // Vulnerability 38: Integer Overflow
  static int calculateTotal(int quantity, int price) {
    // No overflow protection
    return quantity * price; // Could overflow with large values
  }

  // Vulnerability 39: Null Pointer Dereference
  static String processUserData(Map<String, dynamic>? userData) {
    // No null check before accessing
    return userData!['name'].toString().toUpperCase();
  }

  // Vulnerability 40: Regex Denial of Service (ReDoS)
  static bool validateEmail(String email) {
    // Vulnerable regex pattern that can cause catastrophic backtracking
    final regex = RegExp(r'^(([a-z])+.)+[A-Z]([a-z])+$');
    return regex.hasMatch(email);
  }

  // Vulnerability 41: XML External Entity (XXE) Processing
  static void parseXmlUnsafely(String xmlContent) {
    // Simulating XXE vulnerability
    if (xmlContent.contains('<!ENTITY')) {
      print('Processing XML with entities: $xmlContent');
      // In real XML parser, this could lead to file disclosure
    }
  }
}