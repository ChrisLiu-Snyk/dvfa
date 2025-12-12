import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';

class CryptoVulnerabilities {
  
  // Vulnerability 19: Use of MD5 for Security Purposes
  static String hashWithMd5(String input) {
    // Using MD5 which is cryptographically broken
    final bytes = utf8.encode(input);
    final digest = md5.convert(bytes);
    return digest.toString();
  }

  // Vulnerability 20: Use of SHA1 for Security Purposes
  static String hashWithSha1(String input) {
    // Using SHA1 which is deprecated for security use
    final bytes = utf8.encode(input);
    final digest = sha1.convert(bytes);
    return digest.toString();
  }

  // Additional vulnerabilities to reach 20 total new ones:

  // Vulnerability 21: Weak Password Hashing (No Salt)
  static String hashPasswordUnsafely(String password) {
    // Hashing password without salt - vulnerable to rainbow table attacks
    final bytes = utf8.encode(password);
    final digest = sha256.convert(bytes);
    return digest.toString();
  }

  // Vulnerability 22: Predictable IV/Nonce Generation
  static Uint8List generatePredictableIV() {
    // Using predictable IV generation
    final timestamp = DateTime.now().millisecondsSinceEpoch;
    return Uint8List.fromList([
      timestamp & 0xFF,
      (timestamp >> 8) & 0xFF,
      (timestamp >> 16) & 0xFF,
      (timestamp >> 24) & 0xFF,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    ]);
  }

  // Vulnerability 23: Insufficient Key Length
  static Uint8List generateWeakKey() {
    // Generating cryptographic key with insufficient length (64 bits instead of 256)
    final random = Random();
    return Uint8List.fromList(List.generate(8, (_) => random.nextInt(256)));
  }

  // Vulnerability 24: Reusing Cryptographic Keys
  static final Uint8List _reusedKey = Uint8List.fromList([
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
  ]);
  
  static Uint8List getReuseableKey() {
    // Always returning the same key - dangerous for encryption
    return _reusedKey;
  }
}