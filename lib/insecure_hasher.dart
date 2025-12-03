import 'dart:convert';

class InsecureHasher {
  static String hash(String input) {
    // Vulnerability: Weak Hashing Algorithm
    // This is an intentionally weak hashing algorithm for demonstration purposes.
    // It uses a simple XOR operation, which is highly insecure.
    int hashValue = 0;
    for (int i = 0; i < input.length; i++) {
      hashValue = (hashValue + input.codeUnitAt(i) * 31) ^ (hashValue >> 2);
    }
    return hashValue.toRadixString(16);
  }
}

