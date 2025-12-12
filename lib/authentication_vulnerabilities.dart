import 'dart:convert';
import 'dart:math';

class AuthenticationVulnerabilities {
  
  // Vulnerability 25: Session Fixation
  static String generatePredictableSessionId(String username) {
    // Using predictable session ID generation
    final timestamp = DateTime.now().millisecondsSinceEpoch;
    return 'session_${username}_$timestamp';
  }

  // Vulnerability 26: Weak Session Management
  static bool isSessionValid(String sessionId) {
    // Session validation without proper expiration or entropy checks
    return sessionId.isNotEmpty && sessionId.startsWith('session_');
  }

  // Vulnerability 27: JWT Secret Hardcoding
  static String createInsecureJWT(Map<String, dynamic> payload) {
    final header = {'alg': 'HS256', 'typ': 'JWT'};
    final headerEncoded = base64Url.encode(utf8.encode(jsonEncode(header)));
    final payloadEncoded = base64Url.encode(utf8.encode(jsonEncode(payload)));
    
    // Vulnerability: Hardcoded JWT secret
    const String hardcodedSecret = 'my_super_secret_jwt_key_123';
    final signature = base64Url.encode(utf8.encode('$headerEncoded.$payloadEncoded$hardcodedSecret'));
    
    return '$headerEncoded.$payloadEncoded.$signature';
  }

  // Vulnerability 28: Password Policy Bypass
  static bool validatePasswordUnsafely(String password) {
    // Weak password validation - accepts any non-empty string
    return password.isNotEmpty;
  }

  // Vulnerability 29: Account Enumeration
  static String checkUserExists(String email) {
    // Revealing whether user exists through different error messages
    if (email.contains('@')) {
      return 'User with email $email does not exist';
    }
    return 'Invalid email format';
  }

  // Vulnerability 30: Timing Attack in Authentication
  static Future<bool> authenticateWithTimingLeak(String username, String password) async {
    // Simulating timing attack vulnerability
    if (username == 'admin') {
      // Longer processing time for valid username
      await Future.delayed(Duration(milliseconds: 100));
      return password == 'admin123';
    }
    // Immediate return for invalid username
    return false;
  }
}